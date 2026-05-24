package view

import "fmt"

const (
	kib = 1024
	mib = 1024 * kib
	gib = 1024 * mib
	tib = 1024 * gib
)

func humanBytes(n any) string {
	var v float64
	switch x := n.(type) {
	case int:
		v = float64(x)
	case int64:
		v = float64(x)
	case uint64:
		v = float64(x)
	case float64:
		v = x
	default:
		return ""
	}
	if v < kib {
		return fmt.Sprintf("%.0f B", v)
	}
	if v < mib {
		return fmt.Sprintf("%.1f KiB", v/float64(kib))
	}
	if v < gib {
		return fmt.Sprintf("%.1f MiB", v/float64(mib))
	}
	if v < tib {
		return fmt.Sprintf("%.2f GiB", v/float64(gib))
	}
	return fmt.Sprintf("%.2f TiB", v/float64(tib))
}

func addInt64(a, b int64) int64 {
	return a + b
}

