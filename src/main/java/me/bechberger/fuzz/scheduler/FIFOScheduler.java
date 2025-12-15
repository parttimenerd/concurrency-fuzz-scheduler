package me.bechberger.fuzz.scheduler;

import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.map.BPFLRUHashMap;
import me.bechberger.ebpf.runtime.BpfDefinitions;
import me.bechberger.ebpf.runtime.TaskDefinitions;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.fuzz.util.DurationConverter;

import static me.bechberger.ebpf.bpf.BPFJ.*;
import static me.bechberger.ebpf.bpf.Scheduler.PerProcessFlags.PF_KTHREAD;
import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_cpumask_test_cpu;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_LOCAL_ON;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_enq_flags.SCX_ENQ_PREEMPT;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_get_prandom_u32;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_ktime_get_ns;

/**
 * FIFO round-robin scheduler
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "fifo_fuzz_scheduler")
public abstract class FIFOScheduler extends BPFProgram implements Scheduler {

    @Type
    public record DurationRange(@Unsigned long minNs, @Unsigned long maxNs) {

        public DurationRange {
            if (minNs > maxNs) {
                throw new IllegalArgumentException("minNs must be less than or equal to maxNs");
            }
        }

        @Override
        public String toString() {
            return DurationConverter.nanoSecondsToString(minNs, 3) + " - " + DurationConverter.nanoSecondsToString(maxNs, 3);
        }
    }

    @Type
    public record SchedulerSetting(int scriptPID, DurationRange sleepRange, DurationRange runRange, long systemSliceNs, long sliceNs, boolean scaleSlice, boolean log, boolean focusOnJava) {
    }

    @Type
    enum TaskState implements Enum<TaskState> {
        START, RUNNING, SLEEPING
    }

    @Type
    static class TaskContext {

        TaskState state;

        @Unsigned long timeAllowedInState;

        /** Time the task last has been started on the CPU */
        @Unsigned long lastStartNs;
        /** Total runtime of the task since it last slept */
        @Unsigned long runtimeSinceLastSleepNs;
        /** Time the task last has been moved off a CPU */
        @Unsigned long lastStopNs;
    }

    private static final int SHARED_DSQ_ID = 0;

    final GlobalVariable<SchedulerSetting> schedulerSetting = new GlobalVariable<>(new SchedulerSetting(0, new DurationRange(0, 0), new DurationRange(0, 0), 1000000, 1000000, true, false, false));

    @BPFMapDefinition(maxEntries = 10000)
    BPFLRUHashMap<@Unsigned Integer, TaskContext> taskContexts;

    /** Is the task related to the fuzzed script? */
    @BPFMapDefinition(maxEntries = 100000)
    BPFLRUHashMap<@Unsigned Integer, Boolean> isScriptRelated;

    @BPFFunction
    @AlwaysInline
    boolean isTaskScriptRelated(Ptr<TaskDefinitions.task_struct> task) {
        var curPid = task.val().tgid;
        var tgidRel = isScriptRelated.bpf_get(curPid);
        var scriptPid = schedulerSetting.get().scriptPID;
        if (scriptPid == 0) {
            return false;
        }
        if (tgidRel == null) {
            var isRelated = curPid == scriptPid;
            if (!isRelated) {
                // bpf_trace_printk("Process %s has parent %s", task.val().comm, task.val().real_parent.val().comm);
                // check parent process
                var parentTGid = task.val().real_parent.val().tgid;
                var parentPid = task.val().real_parent.val().pid;
                isRelated = parentPid == scriptPid || parentTGid == scriptPid;
            }
            isScriptRelated.put(task.val().pid, isRelated);
            isScriptRelated.put(curPid, isRelated);
            return isRelated;
        }
        return tgidRel.val();
    }

    /**
     * Generate a random number in the range [min, max)
     */
    @BPFFunction
    @Unsigned long randomInRange(@Unsigned long min, @Unsigned long max) {
        if (min == max) {
            return min;
        }
        return min + (bpf_get_prandom_u32() * 31L) % (max - min);
    }

    @BPFFunction
    @AlwaysInline
    void getTaskContext(Ptr<TaskDefinitions.task_struct> task, Ptr<Ptr<TaskContext>> contextPtr) {
        var id = task.val().tgid;
        var ret = taskContexts.bpf_get(id);
        if (ret == null) {
            var context = new TaskContext();
            context.state = TaskState.START;
            context.lastStartNs = 0;
            context.runtimeSinceLastSleepNs = 0;
            context.lastStopNs = 0;
            taskContexts.put(id, context);
        }
        var ret2 = taskContexts.bpf_get(id);
        contextPtr.set(ret2);
    }

    @BPFFunction
    @AlwaysInline
    void initSleeping(Ptr<TaskContext> context, Ptr<TaskDefinitions.task_struct> p) {
        context.val().state = TaskState.SLEEPING;
        context.val().lastStopNs = bpf_ktime_get_ns();
        context.val().timeAllowedInState = randomInRange(schedulerSetting.get().sleepRange.minNs(), schedulerSetting.get().sleepRange.maxNs());
        if (schedulerSetting.get().log()) {
            bpf_trace_printk("%s is sleeping for %dms\n", p.val().comm, context.val().timeAllowedInState / 1_000_000);
        }
    }

    @BPFFunction
    @AlwaysInline
    void initRunning(Ptr<TaskContext> context, Ptr<TaskDefinitions.task_struct> p) {
        context.val().state = TaskState.RUNNING;
        context.val().lastStopNs = bpf_ktime_get_ns();
        context.val().timeAllowedInState = randomInRange(schedulerSetting.get().runRange.minNs(), schedulerSetting.get().runRange.maxNs());
        if (schedulerSetting.get().log()) {
            bpf_trace_printk("%s is running for %dms\n", p.val().comm, context.val().timeAllowedInState / 1_000_000);
        }
    }

    @BPFFunction
    @AlwaysInline
    boolean updateStateIfNeededAndReturnIfSchedulable(Ptr<TaskDefinitions.task_struct> p) {
        if (!isTaskScriptRelated(p)) { // don't schedule tasks that are not related to the script
            return true;
        }
        Ptr<TaskContext> context = null;
        getTaskContext(p, Ptr.of(context));
        if (context == null) {
            return true;
        }
        if (schedulerSetting.get().focusOnJava) {
            if (((p.val().comm[0] == 'C' || p.val().comm[0] == 'G') && (p.val().comm[1] == '1' || p.val().comm[1] == '2')) || (p.val().comm[0] == 'V' && p.val().comm[1] == 'M')) {
                return true;
            }
        }
        if (context.val().state == TaskState.START) { // initialize the task, randomly choose if it should sleep or run
            if (randomInRange(0, 2) == 0) {
                initSleeping(context, p);
                return false;
            } else {
                initRunning(context, p);
                return true;
            }
        }

        if (context.val().state == TaskState.RUNNING) { // check if the task has to sleep
            if (bpf_ktime_get_ns() - context.val().lastStopNs >= context.val().timeAllowedInState) { // sleep if the task has run too long
                initSleeping(context, p);
                return false;
            }
            return true;
        } else { // check if the task can be scheduled again
            if (bpf_ktime_get_ns() - context.val().lastStopNs >= context.val().timeAllowedInState) {
                initRunning(context, p);
                return true;
            }
            return false;
        }
    }

    @Override
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    @Override
    public void enqueue(Ptr<TaskDefinitions.task_struct> p, long enq_flags) {
        var isScriptRelated = isTaskScriptRelated(p);
        @Unsigned long sliceLength = isScriptRelated ? schedulerSetting.get().sliceNs() : schedulerSetting.get().systemSliceNs();
        if (schedulerSetting.get().scaleSlice()) {
            sliceLength = sliceLength / scx_bpf_dsq_nr_queued(SHARED_DSQ_ID);
        }
        scx_bpf_dsq_insert(p, SHARED_DSQ_ID, sliceLength, enq_flags);
    }

    @BPFFunction
    @AlwaysInline
    public boolean tryDispatching(Ptr<BpfDefinitions.bpf_iter_scx_dsq> iter, Ptr<TaskDefinitions.task_struct> p, int cpu) {
        // check if the CPU is usable by the task
        if (!bpf_cpumask_test_cpu(cpu, p.val().cpus_ptr)) {
            return false;
        }
        return scx_bpf_dsq_move(iter, p, SCX_DSQ_LOCAL_ON.value() | cpu, SCX_ENQ_PREEMPT.value());
    }

    @BPFFunction
    @AlwaysInline
    public boolean hasConstraints(Ptr<TaskDefinitions.task_struct> p) {
        return ((p.val().flags & PF_KTHREAD) != 0) || (p.val().nr_cpus_allowed != scx_bpf_nr_cpu_ids());
    }

    @BPFFunction
    @AlwaysInline
    public boolean canScheduleOnCPU(Ptr<TaskDefinitions.task_struct> p, int cpu) {
        return true;
    }

    @Override
    public void dispatch(int cpu, Ptr<TaskDefinitions.task_struct> prev) {
        Ptr<TaskDefinitions.task_struct> p = null;
        bpf_for_each_dsq(SHARED_DSQ_ID, p, iter -> {
            if (!updateStateIfNeededAndReturnIfSchedulable(p)) {
                _continue();
            }
            if ((hasConstraints(p) || canScheduleOnCPU(p, cpu)) && tryDispatching(iter, p, cpu)) {
                return; // has different semantics than continue, return will return from the dispatch function
            }
        });
    }

    @Override
    public void running(Ptr<TaskDefinitions.task_struct> p) {
        if (!isTaskScriptRelated(p)) {
            return;
        }
        Ptr<TaskContext> context = null;
        getTaskContext(p, Ptr.of(context));
        if (context != null) {
            context.val().lastStartNs = bpf_ktime_get_ns();
        }
    }

    @Override
    public void stopping(Ptr<TaskDefinitions.task_struct> p, boolean runnable) {
        if (!isTaskScriptRelated(p)) {
            return;
        }
        Ptr<TaskContext> context = null;
        getTaskContext(p, Ptr.of(context));
        if (context != null) {
            context.val().runtimeSinceLastSleepNs = context.val().runtimeSinceLastSleepNs + (bpf_ktime_get_ns() - context.val().lastStartNs);
        }
    }

    @BPFFunction
    @AlwaysInline
    void setupIsTaskRelatedToScript(Ptr<TaskDefinitions.task_struct> task) {
        var curPid = task.val().tgid;
        var tgidRel = isScriptRelated.bpf_get(curPid);
        var scriptPid = schedulerSetting.get().scriptPID;
        if (scriptPid == 0) {
            return;
        }
        if (tgidRel == null) {
            var isRelated = curPid == scriptPid;
            if (!isRelated) {
               // bpf_trace_printk("Process %s has parent %s", task.val().comm, task.val().real_parent.val().comm);
                // check parent process
                var parentTGid = task.val().real_parent.val().tgid;
                var parentPid = task.val().real_parent.val().pid;
                isRelated = parentPid == scriptPid || parentTGid == scriptPid;
            }
            isScriptRelated.put(task.val().pid, isRelated);
            isScriptRelated.put(curPid, isRelated);
        }
    }

    @Override
    public void enable(Ptr<TaskDefinitions.task_struct> p) {
        setupIsTaskRelatedToScript(p);
    }

    @Override
    public void disable(Ptr<TaskDefinitions.task_struct> p) {
        isScriptRelated.bpf_delete(p.val().tgid);
    }

    public void setSchedulerSetting(SchedulerSetting setting) {
        schedulerSetting.set(setting);
    }
}