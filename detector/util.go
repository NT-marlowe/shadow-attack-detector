package main

const (
	OPEN uint8 = iota
	CLOSE
)

func getSysCallName(sysType uint8) string {
	switch sysType {
	case OPEN:
		return "open"
	case CLOSE:
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
