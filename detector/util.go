package main

func getSysCallName(sysType uint8) string {
	switch sysType {
	case 0:
		return "open"
	case 1:
		return "close"
	default:
		return "unknown"
	}
}

func convertBytesToString(bytes []uint8) string {
	commStr := ""
	for _, b := range bytes[:16] {
		if b == 0 {
			break
		}
		commStr += string(b)
	}
	return commStr
}

func countMap2Dim(m map[uint32]map[uint32]bool) int {
	count := 0
	for _, v := range m {
		count += len(v)
	}
	return count
}
