package scim

import "slices"

func planBulkComponents(operations []BulkOperation) []BulkComponent {
	count := len(operations)
	indexes, low, stacked := make([]int, count), make([]int, count), make([]bool, count)
	for i := range indexes {
		indexes[i] = -1
	}
	var stack []int
	var components []BulkComponent
	next := 0
	// Depth is bounded by BulkPolicy's maximum of 1,000 operations, not input
	// resource nesting. Each edge is from a child to its required predecessor.
	var visit func(int)
	visit = func(index int) {
		indexes[index], low[index] = next, next
		next++
		stack = append(stack, index)
		stacked[index] = true
		for _, predecessor := range operations[index].Dependencies {
			if indexes[predecessor] == -1 {
				visit(predecessor)
				low[index] = min(low[index], low[predecessor])
			} else if stacked[predecessor] {
				low[index] = min(low[index], indexes[predecessor])
			}
		}
		if low[index] != indexes[index] {
			return
		}
		component := BulkComponent{}
		for {
			member := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			stacked[member] = false
			component.Operations = append(component.Operations, member)
			if member == index {
				break
			}
		}
		slices.Sort(component.Operations)
		component.Cyclic = len(component.Operations) > 1 || slices.Contains(operations[index].Dependencies, index)
		components = append(components, component)
	}
	for i := range operations {
		if indexes[i] == -1 {
			visit(i)
		}
	}
	slices.SortFunc(components, func(a, b BulkComponent) int { return a.Operations[0] - b.Operations[0] })
	owner := make([]int, count)
	for i, component := range components {
		for _, operation := range component.Operations {
			owner[operation] = i
		}
	}
	predecessors := make([]map[int]bool, len(components))
	for i, component := range components {
		predecessors[i] = map[int]bool{}
		for _, operation := range component.Operations {
			for _, predecessor := range operations[operation].Dependencies {
				if owner[predecessor] != i {
					predecessors[i][owner[predecessor]] = true
				}
			}
		}
	}
	remaining := make([]int, len(components))
	dependents := make([][]int, len(components))
	for i, dependencies := range predecessors {
		remaining[i] = len(dependencies)
		for predecessor := range dependencies {
			dependents[predecessor] = append(dependents[predecessor], i)
		}
	}
	out := make([]BulkComponent, 0, len(components))
	done := make([]bool, len(components))
	for len(out) < len(components) {
		selected := -1
		for i := range components {
			if !done[i] && remaining[i] == 0 {
				selected = i
				break
			}
		}
		done[selected] = true
		out = append(out, components[selected])
		for _, dependent := range dependents[selected] {
			remaining[dependent]--
		}
	}
	return out
}
