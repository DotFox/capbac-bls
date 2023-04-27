fn main() {
    prost_build::compile_protos(&["src/capbac.proto"],
                                &["src/"]).unwrap();
}
