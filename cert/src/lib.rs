pub mod cert;
pub mod cert_pb;
pub mod errors;
pub mod ca;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
