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

func reconstructPath(bytes []uint8) string {
	path := ""
	i := 0
	prev_i := 0
	for ; i < len(bytes)-1; i++ {
		if bytes[i] == 0 {
			dname := convertBytesToString(bytes[prev_i:i])
			if dname == "/" {
				path = "/" + path
				return path
			}

			if path != "" {
				path = "/" + path
			}
			path = convertBytesToString(bytes[prev_i:i]) + path

			if bytes[i+1] == 0 {
				break
			}

			prev_i = i + 1
			i++
		}
	}
	return path
}
