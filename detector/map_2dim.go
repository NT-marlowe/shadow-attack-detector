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

func (m Map2Dim[K1, K2, V]) HasKey1(key K1) bool {
	_, ok := m[key]
	return ok
}

func (m Map2Dim[K1, K2, V]) HasKey2(key1 K1, key2 K2) bool {
	if _, ok := m[key1]; !ok {
		return false
	}
	_, ok := m[key1][key2]
	return ok
}

type StringUintKey struct {
	Key1 string
	Key2 uint32
}
