package main

import "testing"

func TestGroupPoolsByPriorityAndWeight(t *testing.T) {
	t.Parallel()

	poolA := &tokenPool{label: "A", priority: 100, weight: 3}
	poolB := &tokenPool{label: "B", priority: 100, weight: 1}
	poolC := &tokenPool{label: "C", priority: 80, weight: 2}

	groups := groupPoolsByPriority([]*tokenPool{poolB, poolC, poolA})
	if len(groups) != 2 {
		t.Fatalf("group count = %d, want 2", len(groups))
	}
	if groups[0][0] != poolA {
		t.Fatalf("highest priority group first pool = %p, want poolA", groups[0][0])
	}
	if groups[1][0] != poolC {
		t.Fatalf("second group first pool = %p, want poolC", groups[1][0])
	}

	orderSeed0 := weightedPoolOrder(groups[0], 0)
	if len(orderSeed0) != 2 {
		t.Fatalf("weightedPoolOrder len = %d, want 2", len(orderSeed0))
	}
	if orderSeed0[0] != poolA {
		t.Fatalf("seed 0 first pool = %p, want poolA", orderSeed0[0])
	}

	orderSeed3 := weightedPoolOrder(groups[0], 3)
	if orderSeed3[0] != poolB {
		t.Fatalf("seed 3 first pool = %p, want poolB", orderSeed3[0])
	}
}
