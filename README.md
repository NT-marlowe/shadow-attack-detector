# Shadow Attack Detector

A system that detects shadow attack via online analysis effectively with the help of eBPF.

## What is Shadow Attack?
Please refer to [this thesis](https://people.engr.tamu.edu/guofei/paper/ShadowAttacks_final-onecolumn.pdf).

## Techniques
Fetch the length of C-style string in eBPF.
```c
 static __always_inline u32 string_length(const unsigned char *str) {
 	char tmp_buf[DNAME_LEN] = {0};
 	long ret = bpf_probe_read_kernel_str(tmp_buf, DNAME_LEN, str);
 	if (ret < 0) {
 		return 0;
 	}
 	return ret;
 }
```

## Contact
Please send me a DM via X (former Twitter)
