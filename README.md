Concurrency Fuzz Scheduler
===========

__Disclaimer: This is a proof of concept and highly experimental. Use at your own risk.__

A scheduler that creates random scheduling edge cases and is written in Java using [hello-ebpf](https://github.com/parttimenerd/hello-ebpf).

This is the code for the FOSDEM'25 talk [Concurrency Testing using Custom Linux Schedulers](https://fosdem.org/2025/schedule/event/fosdem-2025-4489-concurrency-testing-using-custom-linux-schedulers/):

> Consider you want to have a concurrency bug that requires threads to run in a specific order.
> Wouldn't it be great if you could stop and start threads at random? Prevent them from being
> scheduled onto the CPU? And the best part: Without the application being able to prevent this,
> like it could do with POSIX STOP and START signals? In come the scheduler extensions for the Linux Kernel.
> Introduced in version 6.12, they allow you to quickly write your own schedulers with eBPF,
> and can be the base for simple libraries that enable you to start and stop threads directly in the Linux kernel.
> This opens the possibility of creating complex scheduler scenarios at a whim.
>
> In this talk, we'll show you a prototypical sched_ext-based library for concurrency testing.

If you want to learn even more on the general concepts, I can recommend reading the excellent [LWN article](https://lwn.net/SubscriberLink/1007689/922423e440f5e68a/).

## Usage

```
./scheduler.sh --help
Usage: scheduler.sh [-dhV] [--java] [--log] [-e=<errorCommand>]
                    [--error-check-interval=<errorCheckIntervalNs>]
                    [-i=<iterationTimeNs>] [-m=<maxIterations>] [-r=<runRange>]
                    [-s=<sleepRange>] [--slice=<sliceNs>]
                    [--system-slice=<systemSliceNs>] script
Linux scheduler that produces random scheduling edge case to fuzz concurrent
applications, runs till error
      script                 Script or command to execute
  -d, --dont-scale-slice     Don't scale the slice time with the number of
                               waiting tasks
  -e, --error-command=<errorCommand>
                             Command to execute on error, default checks for
                               error code != 0
      --error-check-interval=<errorCheckIntervalNs>
                             Time between two checks via the error script
  -h, --help                 Show this help message and exit.
  -i, --iteration-time=<iterationTimeNs>
                             Time to run the script for at a time, restart the
                               whole process afterwards
      --java                 Focus on Java application threads
      --log                  Log the state changes
  -m, --max-iterations=<maxIterations>
                             Maximum number of iterations
  -r, --run=<runRange>       Range of running time lengths
  -s, --sleep=<sleepRange>   Range of sleep lengths
      --slice=<sliceNs>      Time slice duration for the script
      --system-slice=<systemSliceNs>
                             Time slice duration for all non-script tasks
  -V, --version              Print version information and exit.
```

## Example

The sample Java program [samples/Queue.java](samples/Queue.java) is a tiny producer-consumer example:

![Visualization of the Queue.java program](img/queue_sample.png)

The producer produces an item every 20ms and puts it in the queue from which the consumer takes a new item every 10ms.
The consumer crashes the program whenever an item is older than 1s. This is modelled after a real-world issue
I had while developing a profiler for OpenJDK.

You can run the program directly and it shouldn't crash:

```sh
# Compile the program
samples/build_queue.sh
# Run the program
samples/run_queue.sh
```

Even using [stress-ng](https://github.com/ColinIanKing/stress-ng) it shouldn't crash.

But we can run it with the custom fuzz scheduler and create an erratic scheduling behavior that leads to a crash, e.g.:

```sh
> ./scheduler.sh samples/run_queue.sh --log --java
Iteration
[4.293] java is sleeping for 586ms
[4.886] java is running for 5ms
[4.886] java is sleeping for 2241ms
[7.132] java is running for 10ms
[7.144] java is sleeping for 299ms
[7.445] java is running for 3ms
[7.449] java is sleeping for 1038ms
[8.606] java is running for 6ms
[8.611] java is sleeping for 827ms
[9.435] java is running for 10ms
[9.446] java is sleeping for 1543ms
[10.990] java is running for 16ms
[11.012] java is sleeping for 754ms
[11.767] java is running for 15ms
[11.792] Producer is sleeping for 299ms
[12.092] Producer is running for 14ms
[12.111] Producer is sleeping for 1605ms
[13.719] Producer is running for 5ms
[13.731] Consumer is sleeping for 301ms
[14.034] Consumer is running for 12ms
[14.054] Producer is sleeping for 1783ms
[15.839] Producer is running for 15ms
[15.860] Producer is sleeping for 285ms
[16.146] Producer is running for 5ms
[16.156] Consumer is sleeping for 968ms
# ...
[22.494] Producer is running for 11ms
[22.514] Producer is sleeping for 1815ms
[24.330] Producer is running for 16ms
[24.358] Producer is sleeping for 1174ms
[25.528] Producer is running for 7ms
[25.538] Consumer is sleeping for 1912ms
[27.456] Consumer is running for 3ms
[27.465] Consumer is sleeping for 1177ms
[28.655] Consumer is running for 15ms
[28.662] Consumer is sleeping for 1525ms
[30.187] Consumer is running for 6ms
[30.195] Consumer is sleeping for 475ms
[30.674] Consumer is running for 12ms
Program failed after 30.774
```

## Install

Install a 6.13 (or later) kernel, on Ubuntu use [mainline](https://github.com/bkw777/mainline) if you're on Ubuntu 24.10 or older.

You should also have installed:

- `libbpf-dev`
- clang
- Java 23

Now you just have to build the sound-of-scheduling via:

```sh
mvn package
```

You can speed it up with `mvnd`.

License
=======
GPLv2
