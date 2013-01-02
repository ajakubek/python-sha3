import itertools
import sha3
import sys
import threading
import timeit


def pow2(first_exp, exp_limit):
    return [2**exp for exp in range(first_exp, exp_limit)]

def sha_bench_factory(sha_type, update_size, total_size=4*1024*1024):
    assert update_size <= total_size

    vector = '\0' * update_size

    def sha_bench_func():
        sha = sha_type()
        remaining_size = total_size
        while remaining_size > 0:
            sha.update(vector)
            remaining_size -= update_size
        sha.hexdigest()
    return sha_bench_func

def time_lock_overhead(sha_type, update_size):
    bench_func = sha_bench_factory(sha_type, update_size)

    sys.stdout.write(
        '%s, %u byte updates: ' % (sha_type.__name__, update_size))
    sys.stdout.flush()
    elapsed = timeit.timeit(bench_func, number=10)
    sys.stdout.write('%fs\n' % elapsed)

def threaded_sha_bench_factory(concurrency, sha_type, update_size):
    bench_func = sha_bench_factory(
        sha_type, update_size, 32*1024*1024 / concurrency)

    def threaded_sha_bench_func():
        threads = [threading.Thread(target=bench_func) for i in range(concurrency)]
        for thread in threads:
            thread.start()
        thread.join()
    return threaded_sha_bench_func

def time_concurrent(sha_type, update_size, max_concurrency=4):
    sys.stdout.write(
        '%s, %u byte updates:\n' % (sha_type.__name__, update_size))

    thread_func = threaded_sha_bench_factory(1, sha_type, update_size)
    single_thread_elapsed = timeit.timeit(
        threaded_sha_bench_factory(1, sha_type, update_size), number=10)

    sys.stdout.write('  1 thread: %fs\n' % single_thread_elapsed)

    for num_threads in range(2, max_concurrency+1):
        thread_func = threaded_sha_bench_factory(
            num_threads, sha_type, update_size)
        n_thread_elapsed = timeit.timeit(thread_func, number=10)
        speedup = single_thread_elapsed / n_thread_elapsed
        sys.stdout.write(
            '  %u threads: %fs (%02fx speedup)\n' % \
            (num_threads, n_thread_elapsed, speedup))


if __name__ == '__main__':
    sha_types = [sha3.sha224, sha3.sha256, sha3.sha384, sha3.sha512]

    print('Testing lock overhead...')
    for sha_type, update_size in itertools.product(sha_types, pow2(0, 10)):
        time_lock_overhead(sha_type, update_size)

    print('Testing concurrency...')
    for sha_type, update_size in itertools.product(sha_types, pow2(10, 22)):
        time_concurrent(sha_type, update_size)
