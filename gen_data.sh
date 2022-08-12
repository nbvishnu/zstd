export TEST_FILE="../silesia.tar"
export CHUNK_SIZE="64K"
export BENCHMARK_PY="/home/embg/fbsource/fbcode/data_compression/scripts/benchmark.py"
git checkout tinynn
make clean
MOREFLAGS="-DHUF_FORCE_DECOMPRESS_X1" make zstd -j
mv programs/zstd ./zstd_X1
make clean
MOREFLAGS="-DHUF_FORCE_DECOMPRESS_X2" make zstd -j
mv programs/zstd ./zstd_X2

$BENCHMARK_PY enable
$BENCHMARK_PY run -- ~/zstd/zstd_X1 -b3 -q -q -B$CHUNK_SIZE $TEST_FILE > X1_times.txt
$BENCHMARK_PY run -- ~/zstd/zstd_X2 -b3 -q -q -B$CHUNK_SIZE $TEST_FILE > X2_times.txt
