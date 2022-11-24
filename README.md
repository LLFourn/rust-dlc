# Lloyd's attempt at hacking together a benchmark #2

0. `git clone https://github.com/LLFourn/rust-dlc.git && git checkout lloyd-benchmark`
1. cd `dlc-manager`
2. `cargo run --release -- --n-outcomes 1014 --threshold 4 --n-oracles 8`

Output should be self exaplnitory. This time the benchmark is an apples to apples comparison with our benchmark as long as --model-ecdsa-adaptor is on. 
