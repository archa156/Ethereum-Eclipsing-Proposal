package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"benchgrind/experiment"
)

const seed = 20240711

func main() {
	outDir := flag.String("out", "results", "directory to write CSV output into")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(err)
	}

	fmt.Println("=== Experiment 1: reproduce the unopposed baseline grind ===")
	e1 := experiment.Experiment1ReproduceGrind(5, 20, 200, seed)
	writeExperiment1(filepath.Join(*outDir, "experiment1_grind.csv"), e1)
	final1 := e1[len(e1)-1]
	fmt.Printf("  attacker subnets=5, insertion rate=20, rounds=200\n")
	fmt.Printf("  final attacker bench share = %.3f\n", final1.AttackerBenchShare)
	fmt.Printf("  final attacker entry share = %.3f\n", final1.AttackerEntryShare)
	fmt.Printf("  -> written to %s\n\n", filepath.Join(*outDir, "experiment1_grind.csv"))

	fmt.Println("=== Experiment 2: three-scheme comparison under sustained honest churn ===")
	e2 := experiment.Experiment2SchemeComparison(5, 20, 2, 300, 0.5, seed, seed)
	writeExperiment2(filepath.Join(*outDir, "experiment2_comparison.csv"), e2)
	final2 := e2[len(e2)-1]
	fmt.Printf("  attacker subnets=5, insertion rate=20, honest churn=2, rounds=300\n")
	fmt.Printf("  final baseline share       = %.3f\n", final2.BaselineBenchShare)
	fmt.Printf("  final fraction sampling    = %.3f\n", final2.FractionSamplingBenchShare)
	fmt.Printf("  final deterministic share  = %.3f\n", final2.DeterministicBenchShare)
	fmt.Printf("  -> written to %s\n\n", filepath.Join(*outDir, "experiment2_comparison.csv"))

	fmt.Println("=== Experiment 3: attacker effort curves (rounds to reach 90% bench share) ===")
	rates := []int{2, 5, 10, 20, 40, 80}
	e3 := experiment.Experiment3EffortCurves(5, rates, 0.9, 5000, 15, 0.5, seed)
	writeExperiment3(filepath.Join(*outDir, "experiment3_effort_curves.csv"), e3)
	for _, row := range e3 {
		if row.AvgRounds < 0 {
			fmt.Printf("  %-18s rate=%3d  never reached 90%% in budget (%d/%d seeds)\n",
				row.Scheme, row.InsertionRate, row.ReachedCount, row.Seeds)
		} else {
			fmt.Printf("  %-18s rate=%3d  avg rounds=%.1f (%d/%d seeds reached)\n",
				row.Scheme, row.InsertionRate, row.AvgRounds, row.ReachedCount, row.Seeds)
		}
	}
	fmt.Printf("  -> written to %s\n\n", filepath.Join(*outDir, "experiment3_effort_curves.csv"))

	fmt.Println("=== Experiment 4: honest-node overhead (no attacker present) ===")
	e4 := experiment.Experiment4HonestOverhead(40, 500, 0.5, seed, seed)
	writeExperiment4(filepath.Join(*outDir, "experiment4_honest_overhead.csv"), e4)
	for _, row := range e4 {
		fmt.Printf("  %-18s attempts=%d succeeded=%d rejection_rate=%.3f\n",
			row.Scheme, row.Attempts, row.Succeeded, row.RejectionRate)
	}
	fmt.Printf("  -> written to %s\n\n", filepath.Join(*outDir, "experiment4_honest_overhead.csv"))

	fmt.Println("All experiments complete. Seed =", seed, "(reproducible).")
}

func writeExperiment1(path string, rows []experiment.Experiment1Row) {
	w := newCSV(path)
	defer w.file.Close()
	w.write("round", "attacker_bench_share", "attacker_entry_share")
	for _, r := range rows {
		w.write(strconv.Itoa(r.Round), f(r.AttackerBenchShare), f(r.AttackerEntryShare))
	}
	w.flush()
}

func writeExperiment2(path string, rows []experiment.Experiment2Row) {
	w := newCSV(path)
	defer w.file.Close()
	w.write("round", "baseline_bench_share", "fraction_sampling_bench_share", "deterministic_bench_share")
	for _, r := range rows {
		w.write(strconv.Itoa(r.Round), f(r.BaselineBenchShare), f(r.FractionSamplingBenchShare), f(r.DeterministicBenchShare))
	}
	w.flush()
}

func writeExperiment3(path string, rows []experiment.Experiment3Row) {
	w := newCSV(path)
	defer w.file.Close()
	w.write("scheme", "insertion_rate", "avg_rounds_to_90pct", "reached_count", "seeds")
	for _, r := range rows {
		avg := "NA"
		if r.AvgRounds >= 0 {
			avg = f(r.AvgRounds)
		}
		w.write(r.Scheme, strconv.Itoa(r.InsertionRate), avg, strconv.Itoa(r.ReachedCount), strconv.Itoa(r.Seeds))
	}
	w.flush()
}

func writeExperiment4(path string, rows []experiment.Experiment4Row) {
	w := newCSV(path)
	defer w.file.Close()
	w.write("scheme", "attempts", "succeeded", "rejection_rate")
	for _, r := range rows {
		w.write(r.Scheme, strconv.Itoa(r.Attempts), strconv.Itoa(r.Succeeded), f(r.RejectionRate))
	}
	w.flush()
}

type csvWriter struct {
	file *os.File
	w    *csv.Writer
}

func newCSV(path string) *csvWriter {
	file, err := os.Create(path)
	if err != nil {
		fatal(err)
	}
	return &csvWriter{file: file, w: csv.NewWriter(file)}
}

func (c *csvWriter) write(fields ...string) {
	if err := c.w.Write(fields); err != nil {
		fatal(err)
	}
}

func (c *csvWriter) flush() {
	c.w.Flush()
	if err := c.w.Error(); err != nil {
		fatal(err)
	}
}

func f(v float64) string {
	return strconv.FormatFloat(v, 'f', 4, 64)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
