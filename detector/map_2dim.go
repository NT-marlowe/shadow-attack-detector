package main

type Map2Dim[K1, K2 comparable, V any] map[K1]map[K2]V

// Count the number of elements in a 2-dimensional map.
func (m Map2Dim[K1, K2, V]) CountAllElements() int {
	count := 0
	for _, v := range m {
		count += len(v)
	}
	return count
}
