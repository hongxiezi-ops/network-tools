package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	reset  = "\033[0m"
	green  = "\033[32m"
	red    = "\033[31m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	blue   = "\033[34m"
	bold   = "\033[1m"
	gray   = "\033[90m"
)

type ScanResult struct {
	IP    string
	Alive bool
	RTT   time.Duration
	Port  int
	MAC   string
}

type ScanMode int

const (
	Normal ScanMode = iota
	Slow
	Stealth
)

func delay(min, max int) {
	if min >= max {
		time.Sleep(time.Duration(min) * time.Millisecond)
		return
	}
	rangeVal := max - min
	n := int(time.Now().UnixNano() % int64(rangeVal))
	time.Sleep(time.Duration(min+n) * time.Millisecond)
}

func shuffle(slice []int) {
	n := len(slice)
	for i := n - 1; i > 0; i-- {
		j := int(time.Now().UnixNano() % int64(i+1))
		slice[i], slice[j] = slice[j], slice[i]
	}
}

func checkPort(ip string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}

func probeHost(ip string, timeout time.Duration, mode ScanMode) (bool, time.Duration, int) {
	ports := []int{80, 443, 22, 21, 23, 25, 53, 110, 135, 139, 143,
		445, 993, 1433, 3306, 3389, 5432, 5900, 6379, 8080,
		8443, 27017, 1723, 2375, 2376, 9200, 9300, 11211, 28017, 5000}

	if mode == Stealth {
		shuffle(ports)
	}

	var scanTimeout time.Duration
	switch mode {
	case Slow:
		scanTimeout = timeout * 2
	case Stealth:
		scanTimeout = timeout * 3 / 2
	default:
		scanTimeout = timeout
	}

	portTimeout := scanTimeout / time.Duration(len(ports))
	if portTimeout < 20*time.Millisecond {
		portTimeout = 20 * time.Millisecond
	}

	for _, port := range ports {
		if mode == Stealth {
			delay(0, 100)
		}

		start := time.Now()
		addr := net.JoinHostPort(ip, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", addr, portTimeout)
		if err == nil {
			rtt := time.Since(start)
			conn.Close()
			return true, rtt, port
		}
	}
	return false, 0, 0
}

func portScan(ip string, ports []int, timeout time.Duration, workers int, mode ScanMode) []int {
	var openPorts []int
	var mu sync.Mutex
	var scanned int
	var countMu sync.Mutex

	if mode == Stealth {
		shuffle(ports)
	}

	total := len(ports)
	portChan := make(chan int, total)
	var wg sync.WaitGroup

	done := make(chan struct{})
	go func() {
		for {
			countMu.Lock()
			current := scanned
			countMu.Unlock()

			progress := float64(current) / float64(total) * 100
			barLen := 40
			filled := int(progress / 100 * float64(barLen))

			bar := ""
			for i := 0; i < barLen; i++ {
				if i < filled {
					bar += "█"
				} else {
					bar += "░"
				}
			}

			fmt.Printf("\r%s[扫描中] [%s] %.1f%% (%d/%d)%s", yellow, bar, progress, current, total, reset)

			if current >= total {
				break
			}

			select {
			case <-done:
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				if mode == Stealth {
					delay(0, 50)
				}

				if checkPort(ip, port, timeout) {
					mu.Lock()
					openPorts = append(openPorts, port)
					mu.Unlock()
				}

				countMu.Lock()
				scanned++
				countMu.Unlock()
			}
		}()
	}

	for _, port := range ports {
		portChan <- port
	}
	close(portChan)

	wg.Wait()
	close(done)
	fmt.Println()

	sort.Ints(openPorts)
	return openPorts
}

func ipToInt(ip net.IP) int {
	if len(ip) == 16 {
		return int(ip[12])<<24 | int(ip[13])<<16 | int(ip[14])<<8 | int(ip[15])
	}
	return int(ip[0])<<24 | int(ip[1])<<16 | int(ip[2])<<8 | int(ip[3])
}

func parseTarget(target string) ([]string, error) {
	var ips []string

	if strings.Contains(target, "/") {
		ip, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			return nil, err
		}
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
			ips = append(ips, ip.String())
		}
	} else if strings.Contains(target, "-") {
		parts := strings.SplitN(target, "-", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("无效的范围格式")
		}
		start := net.ParseIP(parts[0])
		end := net.ParseIP(parts[1])
		if start == nil || end == nil {
			return nil, fmt.Errorf("无效的IP地址")
		}

		startInt := ipToInt(start)
		endInt := ipToInt(end)

		if startInt > endInt {
			return nil, fmt.Errorf("开始IP不能大于结束IP")
		}

		current := make(net.IP, len(start))
		copy(current, start)
		for !current.Equal(end) {
			ips = append(ips, current.String())
			incrementIP(current)
		}
		ips = append(ips, end.String())
	} else {
		ip := net.ParseIP(target)
		if ip == nil {
			return nil, fmt.Errorf("无效的IP地址格式")
		}
		ips = append(ips, target)
	}

	return ips, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func getMAC(ip string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			if ipNet.Contains(net.ParseIP(ip)) {
				if iface.HardwareAddr != nil {
					return iface.HardwareAddr.String()
				}
			}
		}
	}
	return ""
}

func parsePorts(input string) ([]int, error) {
	input = strings.TrimSpace(input)

	if input == "" {
		var common []int
		for port := 1; port <= 1024; port++ {
			common = append(common, port)
		}
		return common, nil
	}

	if strings.ToLower(input) == "all" {
		var all []int
		for port := 1; port <= 65535; port++ {
			all = append(all, port)
		}
		return all, nil
	}

	var ports []int
	parts := strings.Split(input, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("无效的端口范围格式")
			}
			start, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return nil, err
			}
			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("端口范围无效")
			}
			for port := start; port <= end; port++ {
				ports = append(ports, port)
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, err
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("端口超出范围")
			}
			ports = append(ports, port)
		}
	}

	return ports, nil
}

func getService(port int) string {
	services := map[int]string{
		80:    "HTTP",
		443:   "HTTPS",
		22:    "SSH",
		21:    "FTP",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		110:   "POP3",
		135:   "RPC",
		139:   "NetBIOS",
		143:   "IMAP",
		445:   "SMB",
		993:   "IMAPS",
		1433:  "MSSQL",
		1723:  "PPTP",
		2375:  "Docker",
		2376:  "DockerTLS",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "Postgres",
		5900:  "VNC",
		6379:  "Redis",
		8080:  "HTTP-Alt",
		8443:  "HTTPS-Alt",
		9200:  "Elastic",
		9300:  "Elastic",
		11211: "Memcache",
		27017: "Mongo",
		28017: "MongoAdmin",
		5000:  "UPnP",
	}

	if desc, ok := services[port]; ok {
		return desc
	}
	return "Service"
}

func showProgress(current, total int) {
	progress := float64(current) / float64(total) * 100
	barLen := 40
	filled := int(progress / 100 * float64(barLen))

	bar := ""
	for i := 0; i < barLen; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}

	fmt.Printf("\r%s[%s] %.1f%% (%d/%d)%s", yellow, bar, progress, current, total, reset)
}

func worker(ipChan <-chan string, resultChan chan<- ScanResult, timeout time.Duration, mode ScanMode, wg *sync.WaitGroup) {
	defer wg.Done()
	for ip := range ipChan {
		alive, rtt, port := probeHost(ip, timeout, mode)
		mac := ""
		if alive {
			mac = getMAC(ip)
		}
		resultChan <- ScanResult{IP: ip, Alive: alive, RTT: rtt, Port: port, MAC: mac}
	}
}

func scan(ips []string, timeout time.Duration, workers int, mode ScanMode) ([]ScanResult, error) {
	if len(ips) == 0 {
		return []ScanResult{}, nil
	}

	if workers <= 0 {
		workers = 10
	}
	if workers > 50 {
		workers = 50
	}

	ipChan := make(chan string, len(ips))
	resultChan := make(chan ScanResult, len(ips))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker(ipChan, resultChan, timeout, mode, &wg)
	}

	go func() {
		for _, ip := range ips {
			if mode == Stealth {
				delay(0, 200)
			}
			ipChan <- ip
		}
		close(ipChan)
	}()

	var results []ScanResult
	progressChan := make(chan bool, len(ips))
	go func() {
		count := 0
		for range progressChan {
			count++
			showProgress(count, len(ips))
		}
	}()

	doneChan := make(chan struct{})
	go func() {
		for result := range resultChan {
			results = append(results, result)
			progressChan <- true
		}
		close(progressChan)
		close(doneChan)
	}()

	wg.Wait()
	close(resultChan)
	<-doneChan

	fmt.Println()

	sort.Slice(results, func(i, j int) bool {
		ipa := net.ParseIP(results[i].IP)
		ipb := net.ParseIP(results[j].IP)
		return ipa.String() < ipb.String()
	})

	return results, nil
}

func banner() {
	fmt.Println()
	fmt.Printf("%s+=======================================================+%s\n", cyan, reset)
	fmt.Printf("%s|  Network Scanner Tool v2.1                            |%s\n", cyan, reset)
	fmt.Printf("%s|  网络扫描工具                                         |%s\n", gray, reset)
	fmt.Printf("%s+=======================================================+%s\n", cyan, reset)
	fmt.Println()
}

func usage() {
	fmt.Printf("%s【使用说明】%s\n", bold, reset)
	fmt.Println("  ├─ 单个IP: 192.168.1.1")
	fmt.Println("  ├─ CIDR格式: 192.168.1.0/24")
	fmt.Println("  └─ 范围格式: 192.168.1.1-192.168.1.100")
	fmt.Println()
}

func getMode(reader *bufio.Reader) ScanMode {
	fmt.Printf("%s【扫描模式】%s\n", bold, reset)
	fmt.Println("  1. 快速模式 - 快速扫描")
	fmt.Println("  2. 慢速模式 - 更稳定")
	fmt.Println("  3. 隐蔽模式 - 避免被检测")
	fmt.Println()
	fmt.Printf("%s请选择扫描模式 (1-3, 默认1): %s", yellow, reset)

	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("%s✗ 读取失败，使用快速模式%s\n", red, reset)
		return Normal
	}

	input = strings.TrimSpace(input)
	switch input {
	case "2":
		fmt.Printf("%s  已选择: 慢速模式%s\n", green, reset)
		return Slow
	case "3":
		fmt.Printf("%s  已选择: 隐蔽模式%s\n", green, reset)
		return Stealth
	default:
		fmt.Printf("%s  已选择: 快速模式%s\n", green, reset)
		return Normal
	}
}

func getTarget(reader *bufio.Reader, maxRetries int) (string, error) {
	for attempt := 1; attempt <= maxRetries; attempt++ {
		fmt.Printf("%s请输入目标 IP/网段 (第 %d/%d 次机会):%s ", yellow, attempt, maxRetries, reset)
		target, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("%s✗ 读取失败%s\n", red, reset)
			continue
		}
		target = strings.TrimSpace(target)
		if target == "" {
			fmt.Printf("%s✗ 输入不能为空%s\n", red, reset)
			continue
		}

		_, err = parseTarget(target)
		if err != nil {
			fmt.Printf("%s✗ 错误: %v%s\n", red, err, reset)
			if attempt < maxRetries {
				fmt.Println()
			}
			continue
		}

		return target, nil
	}

	return "", fmt.Errorf("已达到最大重试次数")
}

func run(reader *bufio.Reader) bool {
	banner()
	usage()

	target, err := getTarget(reader, 3)
	if err != nil {
		fmt.Printf("%s✗ 错误: %v%s\n", red, err, reset)
		return false
	}

	ips, err := parseTarget(target)
	if err != nil {
		fmt.Printf("%s✗ 错误: %v%s\n", red, err, reset)
		return false
	}

	fmt.Printf("%s请输入超时时间(ms, 默认: 1000):%s ", yellow, reset)
	timeoutStr, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("%s✗ 读取失败，使用默认值%s\n", red, reset)
	}
	timeoutStr = strings.TrimSpace(timeoutStr)
	timeoutMs := 1000
	if t, err := strconv.Atoi(timeoutStr); err == nil && t > 0 {
		if t < 100 {
			fmt.Printf("%s⚠ 超时太小，已调整为 100ms%s\n", yellow, reset)
			timeoutMs = 100
		} else {
			timeoutMs = t
		}
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	fmt.Printf("%s请输入并发数(默认:20, 上限:50):%s ", yellow, reset)
	workersStr, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("%s✗ 读取失败，使用默认值%s\n", red, reset)
	}
	workersStr = strings.TrimSpace(workersStr)
	workers := 20
	if w, err := strconv.Atoi(workersStr); err == nil && w > 0 {
		workers = w
	}
	if workers > 50 {
		fmt.Printf("%s⚠ 已限制为最大 50 并发%s\n", yellow, reset)
		workers = 50
	}

	mode := getMode(reader)

	fmt.Println()
	fmt.Printf("%s═══════════════════════════════════════════════════════%s\n", cyan, reset)
	fmt.Printf("%s  开始扫描...\n", blue)
	fmt.Printf("%s    目标数量: %d 个\n", gray, len(ips))
	fmt.Printf("%s    超时时间: %dms\n", gray, timeoutMs)
	fmt.Printf("%s    并发数量: %d\n", gray, workers)
	modeStr := "快速"
	if mode == Slow {
		modeStr = "慢速"
	} else if mode == Stealth {
		modeStr = "隐蔽"
	}
	fmt.Printf("%s    扫描模式: %s\n", gray, modeStr)
	fmt.Printf("%s═══════════════════════════════════════════════════════%s\n", cyan, reset)
	fmt.Println()

	fmt.Printf("%s正在扫描中...%s\n", yellow, reset)
	results, err := scan(ips, timeout, workers, mode)
	if err != nil {
		fmt.Printf("%s✗ 错误: %v%s\n", red, err, reset)
		return false
	}

	var aliveIPs []ScanResult
	for _, r := range results {
		if r.Alive {
			aliveIPs = append(aliveIPs, r)
		}
	}

	fmt.Printf("%s═══════════════════════════════════════════════════════%s\n", cyan, reset)
	fmt.Printf("%s  扫描结果\n", blue)
	fmt.Printf("%s═══════════════════════════════════════════════════════%s\n", cyan, reset)

	if len(aliveIPs) == 0 {
		fmt.Printf("  %s[!] 未发现活跃IP%s\n", yellow, reset)
		fmt.Printf("%s═══════════════════════════════════════════════════════%s\n", cyan, reset)
		return true
	}

	fmt.Printf("%s  发现 %d 个活跃IP：\n", yellow, len(aliveIPs))
	fmt.Println()

	for i, r := range aliveIPs {
		rttColor := green
		if r.RTT > 500*time.Millisecond {
			rttColor = yellow
		}
		macStr := r.MAC
		if macStr == "" {
			macStr = gray + "未知" + reset
		}
		desc := getService(r.Port)
		fmt.Printf("  %s[%d]%s %-18s %s%-18s%s %s%dms%s 端口:%d(%s)\n",
			green, i+1, reset, r.IP, cyan, macStr, reset, rttColor, r.RTT.Milliseconds(), reset, r.Port, desc)
	}

	fmt.Println()

	fmt.Printf("%s请选择要扫描端口的IP编号（输入 0 跳过）:%s ", yellow, reset)
	selectStr, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("%s✗ 读取失败，跳过端口扫描%s\n", red, reset)
		return true
	}
	selectStr = strings.TrimSpace(selectStr)
	selectNum, err := strconv.Atoi(selectStr)
	if err != nil || selectNum < 0 || selectNum > len(aliveIPs) {
		fmt.Printf("%s✗ 无效选择，跳过端口扫描%s\n", red, reset)
		return true
	}

	if selectNum == 0 {
		fmt.Println("跳过端口扫描")
		return true
	}

	selectedIP := aliveIPs[selectNum-1]
	fmt.Printf("%s  已选择: %s%s\n", green, selectedIP.IP, reset)
	fmt.Println()

	fmt.Printf("%s【端口扫描】%s\n", bold, reset)
	fmt.Println("  ├─ 直接回车: 默认扫描常用端口(1-1024)")
	fmt.Println("  ├─ 输入 'all': 扫描全部端口(1-65535)")
	fmt.Println("  ├─ 单个端口: 80")
	fmt.Println("  ├─ 多个端口: 80,443,22")
	fmt.Println("  └─ 端口范围: 1-100")
	fmt.Println()

	fmt.Printf("%s请输入要扫描的端口:%s ", yellow, reset)
	portsStr, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("%s✗ 读取失败，使用默认端口%s\n", red, reset)
		portsStr = ""
	}

	ports, err := parsePorts(portsStr)
	if err != nil {
		fmt.Printf("%s✗ 错误: %v，使用默认端口%s\n", red, err, reset)
		var defaultPorts []int
		for port := 1; port <= 1024; port++ {
			defaultPorts = append(defaultPorts, port)
		}
		ports = defaultPorts
	}

	fmt.Println()
	fmt.Printf("%s═══════════════════════════════════════════════════════%s\n", cyan, reset)
	fmt.Printf("%s  正在扫描端口: %s%s\n", blue, selectedIP.IP, reset)
	fmt.Printf("%s    扫描端口: %d 个\n", gray, len(ports))
	fmt.Printf("%s═══════════════════════════════════════════════════════%s\n", cyan, reset)
	fmt.Println()

	fmt.Printf("%s正在扫描端口...%s\n", yellow, reset)
	openPorts := portScan(selectedIP.IP, ports, timeout, 50, mode)

	fmt.Printf("%s═══════════════════════════════════════════════════════%s\n", cyan, reset)
	fmt.Printf("%s  端口扫描结果: %s%s\n", blue, selectedIP.IP, reset)
	fmt.Printf("%s═══════════════════════════════════════════════════════%s\n", cyan, reset)

	if len(openPorts) == 0 {
		fmt.Printf("  %s[!] 未发现开放端口%s\n", yellow, reset)
	} else {
		fmt.Printf("  %s发现 %d 个开放端口：%s\n", green, len(openPorts), reset)
		fmt.Println()
		for _, port := range openPorts {
			desc := getService(port)
			fmt.Printf("  %s[+]%s %-6s %s(%s)%s\n", green, reset, strconv.Itoa(port), yellow, desc, reset)
		}
	}

	fmt.Printf("%s═══════════════════════════════════════════════════════%s\n", cyan, reset)
	fmt.Println()

	deadCount := len(results) - len(aliveIPs)
	rate := float64(len(aliveIPs)) / float64(len(results)) * 100

	fmt.Printf("%s  统计信息\n", blue)
	fmt.Printf("%s═══════════════════════════════════════════════════════%s\n", cyan, reset)
	fmt.Printf("  %s├─ 扫描总数:%s %d\n", gray, reset, len(results))
	fmt.Printf("  %s├─ 活跃数量:%s %s%d%s\n", gray, reset, green, len(aliveIPs), reset)
	fmt.Printf("  %s├─ 不活跃数:%s %s%d%s\n", gray, reset, red, deadCount, reset)
	fmt.Printf("  %s├─ 活跃比率:%s %.2f%%\n", gray, reset, rate)
	if len(openPorts) > 0 {
		fmt.Printf("  %s└─ 开放端口:%s %s%d%s\n", gray, reset, yellow, len(openPorts), reset)
	} else {
		fmt.Printf("  %s└─ 开放端口:%s %s0%s\n", gray, reset, red, 0)
	}
	fmt.Printf("%s═══════════════════════════════════════════════════════%s\n", cyan, reset)
	fmt.Println()

	return true
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	for {
		success := run(reader)
		if !success {
			fmt.Println()
		}

		fmt.Println()
		fmt.Printf("%s【是否继续扫描？】%s\n", bold, reset)
		fmt.Printf("%s请输入 'Y' 或 'y' 继续，其他任意键退出:%s ", yellow, reset)
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("%s✗ 读取失败%s\n", red, reset)
			break
		}

		input = strings.TrimSpace(strings.ToLower(input))
		if input != "y" {
			fmt.Printf("%s感谢使用网络扫描工具，再见！%s\n", green, reset)
			break
		}

		fmt.Println()
		fmt.Println("─────────────────────────────────────────────────────")
		fmt.Println()
	}
}
