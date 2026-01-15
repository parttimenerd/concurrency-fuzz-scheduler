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
            description = "Time to run the script for at a time, restart the whole process afterwards", converter = DurationConverter.class)
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

    /**
     * @return boolean should continue
     */
    boolean iteration() throws InterruptedException, IOException {
        var seed = new Random().nextInt();
        System.out.println("Iteration");
        boolean didProgramFail = false;
        Process process;
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
                if (startTime + iterationTimeNs / 1_000_000 < System.currentTimeMillis()) {
                    break;
                }
                if (timeoutSeconds > 0 && startTime + timeoutSeconds * 1000 < System.currentTimeMillis()) {
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
        return didProgramFail;
    }

    @Override
    public void run() {
        this.startOfFuzzingTime = System.currentTimeMillis();
        DiagramHelper diagram = new DiagramHelper();
        if (log) {
            var logPrintThread = new Thread(() -> {
                double[] firstTimestamp = new double[]{-1};
                TraceLog.getInstance().printLoop(f -> {
                    if (firstTimestamp[0] == -1) {
                        firstTimestamp[0] = f.ts();
                    }
                    var time = f.ts() - firstTimestamp[0];
                    var task = f.msg().split(" is ")[0];
                    var duration = Integer.parseInt(f.msg().split(" for ")[1].split("ms")[0]) / 1000.0;
                    diagram.recordEvent(time, task, f.msg().contains("is sleeping") ? DiagramHelper.EventType.SLEEPING : DiagramHelper.EventType.RUNNING, duration);
                    return String.format("[%03.3f] %s", time, f.msg());
                });
            });
            logPrintThread.setDaemon(true);
            logPrintThread.start();
        }
        for (int i = 0; maxIterations < 0 || i < maxIterations; i++) {
            try {
                if (iteration()) {
                    System.out.printf("Program failed after %.3f%n", (System.currentTimeMillis() - startOfFuzzingTime) / 1000.0);
                    break;
                }
            } catch (Exception e) {
                e.printStackTrace();
                break;
            }
        }
        /*if (log) {
            System.out.println(diagram.createDataJSON());
        }*/
    }


    public static void main(String[] args) {
        var cli = new CommandLine(new Main());
        cli.setUnmatchedArgumentsAllowed(false)
                .execute(args);
    }

}