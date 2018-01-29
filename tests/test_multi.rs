use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use env_logger;
use ZkCluster;

use zookeeper::*;

#[test]
fn multi_creates() {
    let _ = env_logger::init();

    let cluster = ZkCluster::start(3);

    let disconnects = Arc::new(AtomicUsize::new(0));
    let disconnects_watcher = disconnects.clone();

    // Connect to the test cluster
    let zk = ZooKeeper::connect(&cluster.connect_string,
                                Duration::from_secs(5),
                                move |event: WatchedEvent| {
                                    info!("{:?}", event);
                                    if event.keeper_state == KeeperState::Disconnected {
                                        disconnects_watcher.fetch_add(1, Ordering::Relaxed);
                                    }
                                })
        .unwrap();

    let resp = zk.commit(&[Op::Create {
                            path: "/multi-test".to_string(),
                            data: vec![8, 8],
                            acl: Acl::open_unsafe().clone(),
                            mode: CreateMode::Ephemeral
                           },
                           // "/" is probably present
                           Op::Check { path: "/".to_string(), version: None }
                          ]);
    resp.unwrap();

    // Check that we can get the stuff we made in the multi
    zk.get_data("/multi-test", false).unwrap();

    zk.commit(&[Op::Delete { path: "/multi-test".to_string(), version: None },
                Op::Create { path: "/multi-test2".to_string(),
                             data: vec![],
                             acl: Acl::open_unsafe().clone(),
                             mode: CreateMode::Ephemeral },
               ]).unwrap();

    assert!(zk.exists("/multi-test", false).unwrap().is_none());
    assert!(zk.exists("/multi-test2", false).unwrap().is_some());
}
