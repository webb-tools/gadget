use crate::job_manager::SendFuture;
use async_trait::async_trait;
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

pub enum ProceedWithExecution {
    True,
    False,
}

pub trait SendError: Error + Send + 'static {}
impl<T: Error + Send + 'static> SendError for T {}

#[async_trait]
pub trait ExecutableJob: SendFuture<'static, Result<(), Box<dyn SendError>>> + Unpin {
    async fn pre_job_hook(&mut self) -> Result<ProceedWithExecution, Box<dyn SendError>>;
    async fn post_job_hook(&mut self) -> Result<(), Box<dyn SendError>>;
    async fn execute(&mut self) -> Result<(), Box<dyn SendError>> {
        match self.pre_job_hook().await? {
            ProceedWithExecution::True => {
                (&mut self).await?;
                self.post_job_hook().await
            }
            ProceedWithExecution::False => Ok(()),
        }
    }
}

pub struct ExecutableJobWrapper<Pre: ?Sized, Protocol, Post: ?Sized> {
    pre: Pin<Box<Pre>>,
    protocol: Pin<Box<Protocol>>,
    post: Pin<Box<Post>>,
}

#[async_trait]
impl<Pre: ?Sized, Protocol, Post: ?Sized> ExecutableJob
    for ExecutableJobWrapper<Pre, Protocol, Post>
where
    Pre: Future<Output = Result<ProceedWithExecution, Box<dyn SendError>>> + Send + 'static,
    Protocol: SendFuture<'static, Result<(), Box<dyn SendError>>>,
    Post: Future<Output = Result<(), Box<dyn SendError>>> + Send + 'static,
{
    async fn pre_job_hook(&mut self) -> Result<ProceedWithExecution, Box<dyn SendError>> {
        self.pre.as_mut().await
    }

    async fn post_job_hook(&mut self) -> Result<(), Box<dyn SendError>> {
        self.post.as_mut().await
    }
}

impl<Pre, Protocol, Post> ExecutableJobWrapper<Pre, Protocol, Post>
where
    Pre: Future<Output = Result<ProceedWithExecution, Box<dyn SendError>>>,
    Protocol: SendFuture<'static, Result<(), Box<dyn SendError>>>,
    Post: Future<Output = Result<(), Box<dyn SendError>>>,
{
    pub fn new(pre: Pre, protocol: Protocol, post: Post) -> Self {
        Self {
            pre: Box::pin(pre),
            protocol: Box::pin(protocol),
            post: Box::pin(post),
        }
    }
}

impl<Pre: ?Sized, Protocol, Post: ?Sized> Future for ExecutableJobWrapper<Pre, Protocol, Post>
where
    Protocol: SendFuture<'static, Result<(), Box<dyn SendError>>>,
{
    type Output = <Protocol as Future>::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.protocol.as_mut().poll(cx)
    }
}

#[derive(Default)]
pub struct JobBuilder {
    pre: Option<
        Pin<Box<PreJobHook>>,
    >,
    post: Option<Pin<Box<PostJobHook>>>,
}

pub type PreJobHook = dyn SendFuture<'static, Result<ProceedWithExecution, Box<dyn SendError>>>;
pub type PostJobHook = dyn SendFuture<'static, Result<(), Box<dyn SendError>>>;

pub struct DefaultPreJobHook;
impl Future for DefaultPreJobHook {
    type Output = Result<ProceedWithExecution, Box<dyn SendError>>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(ProceedWithExecution::True))
    }
}

pub struct DefaultPostJobHook;
impl Future for DefaultPostJobHook {
    type Output = Result<(), Box<dyn SendError>>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(()))
    }
}

pub type BuiltExecutableJobWrapper<Protocol> = ExecutableJobWrapper<
    dyn SendFuture<'static, Result<ProceedWithExecution, Box<dyn SendError>>>,
    Protocol,
    dyn SendFuture<'static, Result<(), Box<dyn SendError>>>,
>;

impl JobBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pre<Pre>(mut self, pre: Pre) -> Self
    where
        Pre: SendFuture<'static, Result<ProceedWithExecution, Box<dyn SendError>>>,
    {
        self.pre = Some(Box::pin(pre));
        self
    }

    pub fn post<Post>(mut self, post: Post) -> Self
    where
        Post: SendFuture<'static, Result<(), Box<dyn SendError>>>,
    {
        self.post = Some(Box::pin(post));
        self
    }

    pub fn build<Protocol>(self, protocol: Protocol) -> BuiltExecutableJobWrapper<Protocol>
    where
        Protocol: SendFuture<'static, Result<(), Box<dyn SendError>>>,
    {
        let pre = if let Some(pre) = self.pre {
            pre
        } else {
            Box::pin(DefaultPreJobHook)
        };

        let post = if let Some(post) = self.post {
            post
        } else {
            Box::pin(DefaultPostJobHook)
        };

        ExecutableJobWrapper {
            pre,
            protocol: Box::pin(protocol),
            post,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::job::ExecutableJob;

    #[tokio::test]
    async fn test_executable_job_wrapper_proceed() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let counter_clone2 = counter.clone();
        let counter_final = counter.clone();

        let pre = async move {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(super::ProceedWithExecution::True)
        };

        let protocol = async move {
            counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        };

        let post = async move {
            counter_clone2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        };

        let mut job = super::ExecutableJobWrapper::new(pre, protocol, post);
        job.execute().await.unwrap();
        assert_eq!(counter_final.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_executable_job_wrapper_no_proceed() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let counter_clone2 = counter.clone();
        let counter_final = counter.clone();

        let pre = async move {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(super::ProceedWithExecution::False)
        };

        let protocol = async move {
            counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        };

        let post = async move {
            counter_clone2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        };

        let mut job = super::ExecutableJobWrapper::new(pre, protocol, post);
        job.execute().await.unwrap();
        assert_eq!(counter_final.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_job_builder() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let counter_clone2 = counter.clone();
        let counter_final = counter.clone();

        let protocol = async move {
            counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        };

        let mut job = super::JobBuilder::new()
            .pre(async move {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(super::ProceedWithExecution::True)
            })
            .post(async move {
                counter_clone2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .build(protocol);

        job.execute().await.unwrap();
        assert_eq!(counter_final.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_job_builder_no_pre() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let counter_clone2 = counter.clone();
        let counter_final = counter.clone();

        let protocol = async move {
            counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        };

        let mut job = super::JobBuilder::default()
            .post(async move {
                counter_clone2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .build(protocol);

        job.execute().await.unwrap();
        assert_eq!(counter_final.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_job_builder_no_post() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let counter_final = counter.clone();

        let protocol = async move {
            counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        };

        let mut job = super::JobBuilder::default()
            .pre(async move {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(super::ProceedWithExecution::True)
            })
            .build(protocol);

        job.execute().await.unwrap();
        assert_eq!(counter_final.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_job_builder_no_pre_no_post() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let counter_final = counter.clone();

        let protocol = async move {
            counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        };

        let mut job = super::JobBuilder::default().build(protocol);

        job.execute().await.unwrap();
        assert_eq!(counter_final.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
