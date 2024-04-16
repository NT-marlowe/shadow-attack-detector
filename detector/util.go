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
