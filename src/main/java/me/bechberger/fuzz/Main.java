package me.bechberger.fuzz;

import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.shared.TraceLog;
import me.bechberger.ebpf.type.Box;
import me.bechberger.fuzz.scheduler.FIFOScheduler;
import me.bechberger.fuzz.util.DiagramHelper;
import me.bechberger.fuzz.util.DurationConverter;
import me.bechberger.fuzz.util.DurationRangeConverter;
import picocli.CommandLine;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static picocli.CommandLine.Option;
import static picocli.CommandLine.Parameters;

@CommandLine.Command(name = "scheduler.sh", mixinStandardHelpOptions = true,
        description = "Linux scheduler that produces random scheduling edge case to fuzz concurrent applications, runs till error")
public class Main implements Runnable {

    @Parameters(arity = "1", paramLabel = "script", description = "Script or command to execute")
    String script;

    @Option(names = {"-s", "--sleep"}, defaultValue = "10ms,2000ms",
            description = "Range of sleep lengths", converter = DurationRangeConverter.class)
    FIFOScheduler.DurationRange sleepRange;

    @Option(names = {"-r", "--run"}, defaultValue = "1ms,100ms",
            description = "Range of running time lengths", converter = DurationRangeConverter.class)
    FIFOScheduler.DurationRange runRange;

    @Option(names = {"--system-slice"}, defaultValue = "5ms",
            description = "Time slice duration for all non-script tasks", converter = DurationConverter.class)
    long systemSliceNs;

    @Option(names = {"--slice"}, defaultValue = "5ms",
            description = "Time slice duration for the script", converter = DurationConverter.class)
    long sliceNs;

    @Option(names = {"-e", "--error-command"}, defaultValue = "",
            description = "Command to execute on error, default checks for error code != 0")
    String errorCommand;

    @Option(names = {"-i", "--iteration-time"}, defaultValue = "100s",
            description = "Time to run the script for at a time, restart the whole process afterwards, ignored with timeout != 1", converter = DurationConverter.class)
    long iterationTimeNs;

    @Option(names = {"-d", "--dont-scale-slice"}, defaultValue = "false",
            description = "Don't scale the slice time with the number of waiting tasks")
    boolean dontScaleSlice;

    @Option(names = {"-m", "--max-iterations"}, defaultValue = "-1",
            description = "Maximum number of iterations")
    int maxIterations;

    @Option(names = "--error-check-interval", defaultValue = "10s",
            description = "Time between two checks via the error script", converter = DurationConverter.class)
    long errorCheckIntervalNs;

    @Option(names = "--log", defaultValue = "false",
            description = "Log the state changes")
    boolean log;

    @Option(names = "--java", description = "Focus on Java application threads")
    boolean focusOnJava;

    @Option(names = {"-t", "--timeout"}, defaultValue = "-1",
            description = "Maximum time in seconds for a single iteration before treating it as an error/timeout (default: -1, disabled)")
    long timeoutSeconds;

    long startOfFuzzingTime;

    boolean doesErrorScriptSucceed() {
        if (errorCommand.isEmpty()) {
            return false;
        }
        try {
            return new ProcessBuilder("/bin/sh", "-c", errorCommand).start().waitFor() == 0;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    boolean inTimeoutMode() {
        return timeoutSeconds != -1;
    }

    /**
     * @return IterationResult containing duration and failure status
     */
    static class IterationResult {
        final double durationSeconds;
        final boolean didFail;

        IterationResult(double durationSeconds, boolean didFail) {
            this.durationSeconds = durationSeconds;
            this.didFail = didFail;
        }
    }

    IterationResult iteration() throws InterruptedException, IOException {
        var seed = new Random().nextInt();
        System.out.println("Iteration");
        boolean didProgramFail = false;
        Process process;
        long iterationStartTime = System.currentTimeMillis();
        try (var scheduler = BPFProgram.load(FIFOScheduler.class)) {
            // we have a circular dependency here between getting the pid and setting the scheduler setting
            // sleeping for two seconds should prevent any issues

            scheduler.setSchedulerSetting(new FIFOScheduler.SchedulerSetting(0, sleepRange, runRange, systemSliceNs, sliceNs, !dontScaleSlice, log, focusOnJava));

            scheduler.attachScheduler();

            process = new ProcessBuilder(script).start();

            scheduler.setSchedulerSetting(new FIFOScheduler.SchedulerSetting((int) process.pid(), sleepRange, runRange, systemSliceNs, sliceNs, !dontScaleSlice, log, focusOnJava));

            long startTime = System.currentTimeMillis();
            long lastErrorCheckTime = System.currentTimeMillis();
            while (scheduler.isSchedulerAttachedProperly()) {
                Thread.sleep(100);
                if (!process.isAlive()) {
                    if (process.exitValue() != 0) {
                        didProgramFail = true;
                    }
                    break;
                }
                if (System.currentTimeMillis() > lastErrorCheckTime + errorCheckIntervalNs / 1_000_000) {
                    if (doesErrorScriptSucceed()) {
                        didProgramFail = true;
                        break;
                    }
                }
                if (!inTimeoutMode()) {
                    if (startTime + iterationTimeNs / 1_000_000 < System.currentTimeMillis()) {
                        break;
                    }
                } else if (startTime + timeoutSeconds * 1000 < System.currentTimeMillis()) {
                    didProgramFail = true;
                    System.out.println("Iteration timed out");
                    break;
                }
            }
        }
        while (process.isAlive()) {
            process.destroy();
            System.out.println("Killing process");
            Thread.sleep(100);
        }
        double duration = (System.currentTimeMillis() - iterationStartTime) / 1000.0;
        return new IterationResult(duration, didProgramFail);
    }

    @Override
    public void run() {
        this.startOfFuzzingTime = System.currentTimeMillis();
        List<Double> iterationDurations = new ArrayList<>();
        DiagramHelper diagram = new DiagramHelper();
        double[] firstTimestamp = new double[]{-1 /* overall */, -1 /* iteration */};
        if (log) {
            var logPrintThread = new Thread(() -> {
                TraceLog.getInstance().printLoop(f -> {
                    if (firstTimestamp[0] == -1) {
                        firstTimestamp[0] = f.ts();
                    }
                    if (firstTimestamp[1] == -1) {
                        firstTimestamp[1] = f.ts();
                    }
                    var time = f.ts() - firstTimestamp[0];
                    var timeSinceIterationStart = f.ts() - firstTimestamp[1];
                    var task = f.msg().split(" is ")[0];
                    try {
                        var duration = Integer.parseInt(f.msg().split(" for ")[1].split("ms")[0]) / 1000.0;
                        diagram.recordEvent(time, task, f.msg().contains("is sleeping") ? DiagramHelper.EventType.SLEEPING : DiagramHelper.EventType.RUNNING, duration);
                    } catch (Exception ignored) {
                    }
                    return String.format("[%6.3f|%6.3f] %s", time, timeSinceIterationStart, f.msg());
                });
            });
            logPrintThread.setDaemon(true);
            logPrintThread.start();
        }
        for (int i = 0; maxIterations < 0 || i < maxIterations; i++) {
            try {
                firstTimestamp[1] = -1;
                IterationResult result = iteration();
                iterationDurations.add(result.durationSeconds);

                if (log) {
                    printIterationStats(iterationDurations);
                    System.out.println();
                }

                if (result.didFail) {
                    System.out.printf("Program failed after %.3f%n", (System.currentTimeMillis() - startOfFuzzingTime) / 1000.0);
                    break;
                }
            } catch (Exception e) {
                e.printStackTrace();
                break;
            }
        }

        // Print iteration statistics
        if (!iterationDurations.isEmpty() && !log) {
            printIterationStats(iterationDurations);
        }

        /*if (log) {
            System.out.println(diagram.createDataJSON());
        }*/
    }

    private void printIterationStats(List<Double> durations) {
        int count = durations.size();
        double sum = 0;
        double min = Double.MAX_VALUE;
        double max = Double.MIN_VALUE;

        for (double duration : durations) {
            sum += duration;
            min = Math.min(min, duration);
            max = Math.max(max, duration);
        }

        double mean = sum / count;

        // Calculate standard deviation
        double sumSquaredDiff = 0;
        for (double duration : durations) {
            double diff = duration - mean;
            sumSquaredDiff += diff * diff;
        }
        double stdDev = Math.sqrt(sumSquaredDiff / count);

        System.out.println();
        System.out.println("Iteration Count: " + count);
        System.out.printf("Iteration Duration: mean=%.1fs+-%.1fs,min=%.1fs,max=%.1fs%n",
                         mean, stdDev, min, max);
    }


    public static void main(String[] args) {
        var cli = new CommandLine(new Main());
        cli.setUnmatchedArgumentsAllowed(false)
                .execute(args);
    }

}