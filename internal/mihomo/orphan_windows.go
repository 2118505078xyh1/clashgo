package mihomo

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// killOrphans 清理上一次异常退出遗留的内核进程。
//
// 场景：ClashGo 被任务管理器强杀、或崩溃时，mihomo 子进程不会跟着退出，
// 变成孤儿继续占用 mixed-port 和 external-controller。下次启动时新内核
// 会报 "bind: address already in use" 而起不来，界面看到的是旧配置。
//
// 这里只杀「用同一个工作目录、同一个可执行文件」启动的内核，
// 避免误伤用户自己跑的 mihomo。
func killOrphans(bin, controller, workDir string) {
	if controller == "" {
		return
	}
	port := portOf(controller)
	if port == 0 {
		return
	}

	if runtime.GOOS == "windows" {
		killOrphansWindows(bin, port)
		return
	}
	killOrphansUnix(bin)
}

// portOf 从 "127.0.0.1:9097" 里取出端口号。
func portOf(addr string) int {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return 0
	}
	p, err := strconv.Atoi(addr[idx+1:])
	if err != nil {
		return 0
	}
	return p
}

// killOrphansWindows 在 Windows 上按可执行路径 + 监听端口定位孤儿进程。
func killOrphansWindows(bin string, port int) {
	// 用 netstat 找出占用该端口的 PID。
	out, err := exec.Command("netstat", "-ano", "-p", "tcp").Output()
	if err != nil {
		return
	}
	pids := pidsListeningOn(string(out), port)
	for _, pid := range pids {
		if pid == 0 {
			continue
		}
		// 确认这个进程确实是 mihomo（路径匹配），避免误杀别的程序。
		exePath, err := exec.Command("tasklist", "/FI", "PID eq "+strconv.Itoa(pid),
			"/FO", "CSV", "/NH").Output()
		if err != nil {
			continue
		}
		name := strings.ToLower(firstCSVField(string(exePath)))
		if !strings.Contains(name, "mihomo") && !strings.Contains(name, "clash") {
			continue
		}
		_ = exec.Command("taskkill", "/F", "/PID", strconv.Itoa(pid)).Run()
	}
	// 给操作系统一点时间回收端口。
	time.Sleep(300 * time.Millisecond)
}

// killOrphansUnix 在类 Unix 系统上按可执行路径匹配并结束进程。
func killOrphansUnix(bin string) {
	out, err := exec.Command("pgrep", "-f", bin).Output()
	if err != nil {
		return
	}
	for _, line := range strings.Fields(string(out)) {
		pid, err := strconv.Atoi(line)
		if err != nil || pid == 0 {
			continue
		}
		_ = exec.Command("kill", "-9", strconv.Itoa(pid)).Run()
	}
	time.Sleep(300 * time.Millisecond)
}

// pidsListeningOn 从 netstat 输出里找出监听指定端口的 PID。
func pidsListeningOn(netstat string, port int) []int {
	want := ":" + strconv.Itoa(port)
	var pids []int
	for _, line := range strings.Split(netstat, "\n") {
		if !strings.Contains(line, "LISTENING") {
			continue
		}
		fields := strings.Fields(line)
		// TCP  0.0.0.0:9097  0.0.0.0:0  LISTENING  1234
		if len(fields) < 5 {
			continue
		}
		local := fields[1]
		if !strings.HasSuffix(local, want) {
			continue
		}
		pid, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	return pids
}

// firstCSVField 取 CSV 第一行第一列（去掉引号）。
func firstCSVField(s string) string {
	line := strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
	line = strings.Trim(line, "\"")
	if i := strings.Index(line, "\","); i >= 0 {
		line = strings.Trim(line[:i], "\"")
	}
	return line
}
