# python-rsa by rust
encrypt messag by RSA private for python

cargo >= 1.88

install:
maturin build --release

pip install src/target/wheels/rsa-0.1.0-cp39-cp39-macosx_10_12_x86_64.whl

or

maturin develop
