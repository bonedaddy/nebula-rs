use tokio_tun;
use anyhow::Result;


pub fn new_tunnel() -> Result<()> {
    tokio_tun::TunBuilder::new();

    Ok(())
}


 

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
