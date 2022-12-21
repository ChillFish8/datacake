use crate::{DatacakeNode, ServiceRegistry};
use async_trait::async_trait;
use tonic::transport::server::Router;

#[async_trait]
/// An extension of the base node/cluster.
///
/// This can be used to extend a base node to include additional
/// functionality, like the eventually consistent store, multi-raft cluster
/// or anything else which may want to use the membership, rpc and clock system.
pub trait ClusterExtension: ServiceRegistry {
    type Output;
    type Error;

    async fn init_extension(self, node: &DatacakeNode) -> Result<Self::Output, Self::Error>;
}
