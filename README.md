# python-rsa by rust
encrypt messag by RSA private for python

cargo >= 1.88

export PYO3_PYTHON=/usr/bin/python3.9

install:

pip install maturin

maturin build --release

pip install src/target/wheels/rsa-0.1.0-cp39-cp39-macosx_10_12_x86_64.whl

or

maturin develop

usage :

import custody_rsa

priv='MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDSxEURQHg5zk/6g7laQhXjAhUkPj59kwwtFm3Lv+aBplMYs+miFMK32xhL+XWXq0jTM3DX63YX+J9yQLuKo6fbzlQIil+4wXD8v1liVOM9RAA3dkeJIiOGZQZ2GKJyBsQIdJY3+n5A71MrCE5imVy/LA4iX3SKLtY7HkgruWWRHytQTK22jCxSa0hpltaqeONMUBfjRxFftXUrapVyFUFynzq/iuW3Q49pPgT4rXqSGUg+IO2IStVJnJSkHWlC94PQklNidRvafTslpSVQUCn0e6fLcOZEYM6BK82Id6sxeqOWRcNpoYwsBfJ4em5QPF4XhBuFtD7mGwwEmhqLlf25AgMBAAECggEBAId7wyoj1yTRinfu1OdAM/GJFS4HFQSD0f/puwqOgQ42bJQkkrqtvb2SCTxNT1n/sQCSwKcLpQ4js9st4WBtcynIqBwVVxLcxlSybDLZfnmTjNAaKEHuwAdUSaMAkuvZjYoh5650R1RWg4/V9w1KqGP7Xdqaob9x/CRkguAYfUGbK8Hurv4uRJnTYDHwDTeOLyXp21Ow4mbukQUMDiqLEqx5sF805f2jW5V2AICRn/k/lgObLkrvCsYEOHaM+vsdrZL40gMjCux0i6ECNAaZaaj54pWUFqik23H0Rzt2cdxstQiDQFEdG3o8vGNWtsQ+qqagArCWpi9z2YQIe4KfcEECgYEA/tG/2Azg3+AblyfyULip5sNYrTxGRq2kkrNqyYk7FmsHdqzTH4TzfrlRgGkXGJb1zeRkL6/6PowTvIeAVkZVv0IVl2jel6lROAyuPGNKDmlDaS0bpdI4CUL13D5AbBAp267kOWBrbREn0cBj4KQO2qrAcoYcihWa6C0oVV/CbzsCgYEA075ElsaP9fZMOoJlCe7rbvJnUWNbFD/RWMXMicE5d8sjsggvbf7redVxrumCi4c+/2+CS9txOPt5fdG3HzA1A8AhsvUVs6RjxYTNjr4UG1W5GReI/+gfmzMH/s5csgkdVrMFs+odQIGvOVEz2s363VQA9D+0vHVWX/o9Xgrln5sCgYB+VKiiyQe3lhi3oLNOd66r3E8bW5WPtsivfknD7sgffiJuIJJuvvAk9GVGn1M2+qiUUdWlmr4awkGKpzbmDuq17mJb9T7du7CrdAXxpFvztxYXj6h0Vjs3xD212hsAOCc4ZYV6OKYppWazY4lgtpUyrZLJdFmzz7BDyReE8/umPwKBgGRy1LL6S30RdKQlC62krAeb8yuHCMQYakXEv/1xrsOHmM1yWJ3D2w2XFjE2EXoDlP00dwlpdtLjaYUoocin4959nP76iWsJR1OCZsmanotBJWgj5BgSlDvZ/6b/WrYS4NoqX0A0hd/+JZP5U7IvGR06JqG4PxNQTsOFQOuGG9yVAoGBANH0knupfdxgvnPOSapnyhq99C8rsLGEkoh7KoqWCCsFPoMcWjyHwpOxukkPKPDEY5j8JnX3vzPofpUVv4REEUuTnZjezPMwDbrWAQ/0kQztTZOSMtpjpGDvHHgc3I02okI0mrGNQPvQwRVwe0IcJ/X4ddjF1OQLD6tK1sekku5n'

data='{"code":"0","data":[{"coin_net":"Bitcoin","symbol":"BTC","address_tag_regex":"","address_regex":"\\"^(1|3)[a-zA-Z0-9]{24,36}$\\",\\"^bc[a-zA-Z0-9]+\\"","coin_type":1,"support_memo":"0","icon":"https://fin-tech-vip.oss-ap-southeast-1.aliyuncs.com/saas/1660016073924.png","support_multi_addr":true,"support_acceleration":true,"contract_address":"","symbol_alias":"BTC","merge_address_symbol":"BTC","txid_link":"https://explorer.btc.com/btc/transaction/","decimals":"8","base_symbol":"BTC","address_link":"https://explorer.btc.com/btc/address/","deposit_confirmation":"1","support_token":"1","real_symbol":"BTC","if_open_chain":true}],"msg":"success"}'

pub='MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0sRFEUB4Oc5P+oO5WkIV4wIVJD4+fZMMLRZty7/mgaZTGLPpohTCt9sYS/l1l6tI0zNw1+t2F/ifckC7iqOn285UCIpfuMFw/L9ZYlTjPUQAN3ZHiSIjhmUGdhiicgbECHSWN/p+QO9TKwhOYplcvywOIl90ii7WOx5IK7llkR8rUEyttowsUmtIaZbWqnjjTFAX40cRX7V1K2qVchVBcp86v4rlt0OPaT4E+K16khlIPiDtiErVSZyUpB1pQveD0JJTYnUb2n07JaUlUFAp9Huny3DmRGDOgSvNiHerMXqjlkXDaaGMLAXyeHpuUDxeF4QbhbQ+5hsMBJoai5X9uQIDAQAB'

en_data=custody_rsa.private_key_encrypt(pri,data)

custody_rsa.public_key_decrypt(pub, en_data)

