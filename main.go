package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
)

type FileInfo struct {
	Name        string
	Path        string
	Size        int64
	ModTime     time.Time
	IsDirectory bool
	MD5Hash     string
	SHA256Hash  string
	Ext         string
	MimeType    string
}

// 文件分组信息
type FileGroup struct {
	ID        string
	Size      int64
	Count     int
	Files     []FileInfo
	HashType  string // "MD5" 或 "SHA256"
	HashValue string
}

// 获取文件类型信息
func getFileType(path string, info os.FileInfo) (ext, mimeType string) {
	// 获取文件扩展名
	ext = strings.ToLower(filepath.Ext(path))
	if ext != "" {
		ext = ext[1:] // 移除点号
	}

	// 获取MIME类型
	if !info.IsDir() {
		mimeType = mime.TypeByExtension(filepath.Ext(path))
		if mimeType == "" {
			// 尝试从文件名判断
			mimeType = mime.TypeByExtension("." + ext)
		}
	}

	return ext, mimeType
}

// 计算文件的MD5哈希值
func calculateMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// 计算文件的SHA256哈希值
func calculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// 进度条结构
type Progress struct {
	Total     int64
	Current   int64
	Mutex     sync.Mutex
	StartTime time.Time
	Bar       *progressbar.ProgressBar
}

func (p *Progress) Increment() {
	p.Mutex.Lock()
	p.Current++
	p.Bar.Add(1)
	p.Mutex.Unlock()
}

func (p *Progress) Print() {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()

	elapsed := time.Since(p.StartTime)
	speed := float64(p.Current) / elapsed.Seconds()

	// 更新进度条描述
	p.Bar.Describe(fmt.Sprintf("速度: %.1f 文件/秒", speed))
}

// 文件处理任务
type FileTask struct {
	Path     string
	Info     os.FileInfo
	RelPath  string
	AbsDir   string
	Progress *Progress
}

// 检查文件是否满足大小要求
func isFileSizeValid(size int64, minSize int64) bool {
	return size >= minSize
}

// 文件大小单位转换
func formatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}

	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"B", "KB", "MB", "GB", "TB"}
	if exp >= len(units) {
		exp = len(units) - 1
	}

	return fmt.Sprintf("%.2f %s", float64(size)/float64(div), units[exp])
}

// 将MB转换为字节
func mbToBytes(mb float64) int64 {
	return int64(mb * 1024 * 1024)
}

// 处理单个文件
func processFile(task FileTask, writer *csv.Writer, writerMutex *sync.Mutex, fileGroups map[string]*FileGroup, groupsMutex *sync.Mutex) error {
	// 初始化哈希值
	md5Hash := ""
	sha256Hash := ""

	// 获取文件类型信息
	ext, mimeType := getFileType(task.Path, task.Info)

	// 计算文件哈希值
	md5Hash, err := calculateMD5(task.Path)
	if err != nil {
		return fmt.Errorf("计算文件 %s 的MD5哈希值失败: %v", task.Path, err)
	}

	sha256Hash, err = calculateSHA256(task.Path)
	if err != nil {
		return fmt.Errorf("计算文件 %s 的SHA256哈希值失败: %v", task.Path, err)
	}

	// 创建文件信息
	fileInfo := FileInfo{
		Name:        task.Info.Name(),
		Path:        task.RelPath,
		Size:        task.Info.Size(),
		ModTime:     task.Info.ModTime(),
		IsDirectory: task.Info.IsDir(),
		MD5Hash:     md5Hash,
		SHA256Hash:  sha256Hash,
		Ext:         ext,
		MimeType:    mimeType,
	}

	// 更新文件分组
	groupsMutex.Lock()
	var isDuplicate bool
	// 按MD5分组
	if md5Group, exists := fileGroups["MD5:"+md5Hash]; exists {
		md5Group.Count++
		md5Group.Files = append(md5Group.Files, fileInfo)
		isDuplicate = true
	} else {
		fileGroups["MD5:"+md5Hash] = &FileGroup{
			ID:        fmt.Sprintf("MD5_%d", len(fileGroups)+1),
			Size:      task.Info.Size(),
			Count:     1,
			Files:     []FileInfo{fileInfo},
			HashType:  "MD5",
			HashValue: md5Hash,
		}
	}

	// 按SHA256分组
	if sha256Group, exists := fileGroups["SHA256:"+sha256Hash]; exists {
		sha256Group.Count++
		sha256Group.Files = append(sha256Group.Files, fileInfo)
		isDuplicate = true
	} else {
		fileGroups["SHA256:"+sha256Hash] = &FileGroup{
			ID:        fmt.Sprintf("SHA256_%d", len(fileGroups)+1),
			Size:      task.Info.Size(),
			Count:     1,
			Files:     []FileInfo{fileInfo},
			HashType:  "SHA256",
			HashValue: sha256Hash,
		}
	}
	groupsMutex.Unlock()

	// 如果是重复文件，写入CSV
	if isDuplicate {
		// 准备CSV行数据
		row := []string{
			task.Info.Name(),
			task.RelPath,
			fmt.Sprintf("%d", task.Info.Size()),
			formatFileSize(task.Info.Size()),
			task.Info.ModTime().Format("2006-01-02 15:04:05"),
			fmt.Sprintf("%v", task.Info.IsDir()),
			md5Hash,
			sha256Hash,
			ext,
			mimeType,
		}

		// 写入CSV（使用互斥锁保护）
		writerMutex.Lock()
		if err := writer.Write(row); err != nil {
			writerMutex.Unlock()
			return fmt.Errorf("写入CSV行失败: %v", err)
		}
		writerMutex.Unlock()
	}

	// 更新进度
	task.Progress.Increment()
	task.Progress.Print()

	return nil
}

// 工作协程
func worker(id int, tasks <-chan FileTask, wg *sync.WaitGroup, writer *csv.Writer, writerMutex *sync.Mutex, fileGroups map[string]*FileGroup, groupsMutex *sync.Mutex) {
	defer wg.Done()
	for task := range tasks {
		if err := processFile(task, writer, writerMutex, fileGroups, groupsMutex); err != nil {
			fmt.Printf("\n工作协程 %d: %v\n", id, err)
		}
	}
}

// 生成分组报告
func generateGroupReport(fileGroups map[string]*FileGroup, outputDir string) error {
	// 创建分组报告文件
	reportFile, err := os.Create(filepath.Join(outputDir, "duplicate_groups.csv"))
	if err != nil {
		return fmt.Errorf("创建分组报告文件失败: %v", err)
	}
	defer reportFile.Close()

	// 创建CSV写入器
	writer := csv.NewWriter(reportFile)
	defer writer.Flush()

	// 写入CSV头部
	headers := []string{"分组ID", "哈希类型", "哈希值", "文件数量", "文件大小(字节)", "文件大小(可读)", "文件路径列表"}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("写入CSV头部失败: %v", err)
	}

	// 将分组转换为切片以便排序
	var groups []*FileGroup
	for _, group := range fileGroups {
		groups = append(groups, group)
	}

	// 按文件数量降序排序
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Count > groups[j].Count
	})

	// 写入分组数据
	for _, group := range groups {
		if group.Count > 1 { // 只输出重复文件组
			// 准备文件路径列表
			var filePaths []string
			for _, file := range group.Files {
				filePaths = append(filePaths, file.Path)
			}

			// 写入一行数据
			row := []string{
				group.ID,
				group.HashType,
				group.HashValue,
				fmt.Sprintf("%d", group.Count),
				fmt.Sprintf("%d", group.Size),
				formatFileSize(group.Size),
				strings.Join(filePaths, "\n"), // 使用换行符分隔文件路径
			}

			if err := writer.Write(row); err != nil {
				return fmt.Errorf("写入分组数据失败: %v", err)
			}
		}
	}

	return nil
}

// 检查是否是系统文件夹
func isSystemFolder(path string) bool {
	systemFolders := []string{
		"$RECYCLE.BIN",
		"System Volume Information",
		"Recovery",
		"WindowsApps",
		"ProgramData",
		"Config.Msi",
		"Windows.old",
		"WindowsApps",
		"AppData",
		"Local Settings",
		"Application Data",
		"Temporary Internet Files",
		"Templates",
		"Cookies",
		"Recent",
		"SendTo",
		"Start Menu",
		"Programs",
		"Startup",
		"Desktop",
		"Favorites",
		"My Documents",
		"My Pictures",
		"My Music",
		"My Videos",
		"Downloads",
		"Documents",
		"Pictures",
		"Music",
		"Videos",
	}

	// 检查路径中是否包含系统文件夹名
	for _, folder := range systemFolders {
		if strings.Contains(path, folder) {
			return true
		}
	}

	// 检查是否是隐藏文件夹
	if strings.HasPrefix(filepath.Base(path), ".") {
		return true
	}

	return false
}

// 遍历目录并发送任务
func walkDirectory(absDir string, tasks chan<- FileTask, progress *Progress, minSize int64) error {
	return filepath.Walk(absDir, func(path string, info os.FileInfo, err error) error {
		// 处理访问错误
		if err != nil {
			// 如果是权限错误，跳过该目录
			if os.IsPermission(err) {
				fmt.Printf("\n警告：无法访问目录 %s: %v\n", path, err)
				return filepath.SkipDir
			}
			return err
		}

		// 跳过当前目录
		if path == absDir {
			return nil
		}

		// 跳过系统文件夹
		if isSystemFolder(path) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// 跳过不满足大小要求的文件
		if !info.IsDir() && !isFileSizeValid(info.Size(), minSize) {
			return nil
		}

		// 获取相对路径
		relPath, err := filepath.Rel(absDir, path)
		if err != nil {
			return err
		}

		// 如果不是目录，创建任务并发送到通道
		if !info.IsDir() {
			task := FileTask{
				Path:     path,
				Info:     info,
				RelPath:  relPath,
				AbsDir:   absDir,
				Progress: progress,
			}
			tasks <- task
		}

		return nil
	})
}

func main() {
	// 定义命令行参数
	dir := flag.String("dir", ".", "要扫描的目录路径")
	output := flag.String("output", "file_info.csv", "输出CSV文件的路径")
	workers := flag.Int("workers", 4, "并发工作协程数量")
	minSizeMB := flag.Float64("min-size", 1.0, "最小文件大小（MB），默认1MB")
	flag.Parse()

	// 将MB转换为字节
	minSize := mbToBytes(*minSizeMB)

	// 检查目录是否存在
	if _, err := os.Stat(*dir); os.IsNotExist(err) {
		fmt.Printf("错误：目录 '%s' 不存在\n", *dir)
		flag.Usage()
		os.Exit(1)
	}

	// 获取绝对路径
	absDir, err := filepath.Abs(*dir)
	if err != nil {
		fmt.Printf("获取目录绝对路径失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("开始扫描目录: %s\n", absDir)
	fmt.Printf("使用 %d 个工作协程\n", *workers)
	fmt.Printf("最小文件大小: %.1f MB\n", *minSizeMB)

	// 创建输出目录
	outputDir := filepath.Dir(*output)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("创建输出目录失败: %v\n", err)
		return
	}

	// 创建CSV文件
	file, err := os.Create(*output)
	if err != nil {
		fmt.Printf("创建CSV文件失败: %v\n", err)
		return
	}
	defer file.Close()

	// 创建CSV写入器
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入CSV头部
	headers := []string{"文件名", "完整路径", "大小(字节)", "大小(可读)", "修改时间", "是否目录", "MD5哈希值", "SHA256哈希值", "扩展名", "MIME类型"}
	if err := writer.Write(headers); err != nil {
		fmt.Printf("写入CSV头部失败: %v\n", err)
		return
	}

	// 初始化进度条
	progress := &Progress{
		StartTime: time.Now(),
	}

	// 首先计算总文件数
	fmt.Println("正在计算文件总数...")
	err = filepath.Walk(absDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// 如果是权限错误，跳过该目录
			if os.IsPermission(err) {
				fmt.Printf("\n警告：无法访问目录 %s: %v\n", path, err)
				return filepath.SkipDir
			}
			return err
		}

		// 跳过系统文件夹
		if isSystemFolder(path) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// 跳过不满足大小要求的文件
		if !info.IsDir() && !isFileSizeValid(info.Size(), minSize) {
			return nil
		}

		if !info.IsDir() {
			progress.Total++
		}
		return nil
	})

	if err != nil {
		fmt.Printf("计算文件总数失败: %v\n", err)
		return
	}

	fmt.Printf("找到 %d 个文件，开始处理...\n", progress.Total)

	// 创建进度条
	progress.Bar = progressbar.Default(progress.Total)
	progress.Bar.Describe("正在扫描文件...")

	// 创建任务通道
	tasks := make(chan FileTask, progress.Total)
	var wg sync.WaitGroup
	writerMutex := &sync.Mutex{}
	groupsMutex := &sync.Mutex{}
	fileGroups := make(map[string]*FileGroup)

	// 启动工作协程
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(i+1, tasks, &wg, writer, writerMutex, fileGroups, groupsMutex)
	}

	// 遍历目录并发送任务
	err = walkDirectory(absDir, tasks, progress, minSize)

	// 关闭任务通道
	close(tasks)

	// 等待所有工作协程完成
	wg.Wait()

	if err != nil {
		fmt.Printf("\n遍历目录失败: %v\n", err)
		return
	}

	// 生成分组报告
	fmt.Println("\n正在生成重复文件分组报告...")
	if err := generateGroupReport(fileGroups, outputDir); err != nil {
		fmt.Printf("生成分组报告失败: %v\n", err)
		return
	}

	// 统计重复文件信息
	var duplicateGroups, duplicateFiles int
	for _, group := range fileGroups {
		if group.Count > 1 {
			duplicateGroups++
			duplicateFiles += group.Count
		}
	}

	// 打印最终统计信息
	elapsed := time.Since(progress.StartTime)
	fmt.Printf("\n\n扫描完成！\n")
	fmt.Printf("总文件数: %d\n", progress.Total)
	fmt.Printf("重复文件组数: %d\n", duplicateGroups)
	fmt.Printf("重复文件总数: %d\n", duplicateFiles)
	fmt.Printf("总耗时: %.2f 秒\n", elapsed.Seconds())
	fmt.Printf("平均速度: %.1f 文件/秒\n", float64(progress.Total)/elapsed.Seconds())
	fmt.Printf("重复文件信息已成功导出到 %s\n", *output)
	fmt.Printf("重复文件分组报告已导出到 %s\n", filepath.Join(outputDir, "duplicate_groups.csv"))
}
