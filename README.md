# Lloyd's attempt at hacking together a benchmark

0. `git clone https://github.com/LLFourn/rust-dlc.git && git checkout benchmark-hacks`
1. cd `dlc-manager`
1. open `benches/benchmark.rs`
2. Change the parameters `NB_ORACLES THRESHOLD N_OUTCOMES` to your liking
3. Save it
4. run `cargo bench`

You'll get output like this:

```
Warning: Unable to complete 10 samples in 5.0s. You may wish to increase target time to 34.0s.
sign                    time:   [3.4125 s 3.4165 s 3.4207 s]
                        change: [+14.663% +15.148% +15.752%] (p = 0.00 < 0.05)
                        Performance has regressed.

Benchmarking verify: Warming up for 3.0000 s
Warning: Unable to complete 10 samples in 5.0s. You may wish to increase target time to 35.5s.
verify                  time:   [3.5096 s 3.5290 s 3.5492 s]
                        change: [+11.740% +13.508% +15.249%] (p = 0.00 < 0.05)
                        Performance has regressed.

```

To get a total time for the whole protocol add the sign and verify bits together. i.e. `3.4165 + 3.5290 = 6.9455`.

## CAVEATs READ CAREFULLY

1. In our benchmarks we don't include the creation of the signatures themselves. This means these benchmarks have an overhead. To measure this overhead for any number of outcomes set `NB_ORACLES = THRESHOLD = 1` and look at how long sign takes. This is very roughly the overhead.
2. In our benchmarks we use different oracle attesation schemes. Our BLS one is slower than this but our non-pairing one is faster.

