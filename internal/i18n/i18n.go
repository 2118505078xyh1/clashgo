// Package i18n 提供 clashgo 界面的中文文案映射。
// 项目固定使用简体中文，不提供其他语言选项。
package i18n

// Lang 是语言标识（保留类型以兼容既有调用，实际只用中文）。
type Lang string

const (
	ZH Lang = "zh"
	EN Lang = "en"
)

// 界面文案映射：msgid -> 中文。
var dict = map[string]map[Lang]string{
	"home":            {ZH: "首页"},
	"proxies":         {ZH: "代理"},
	"profiles":        {ZH: "配置"},
	"rules":           {ZH: "规则"},
	"connections":     {ZH: "连接"},
	"logs":            {ZH: "日志"},
	"unlock":          {ZH: "媒体解锁"},
	"dns":             {ZH: "DNS 查询"},
	"settings":        {ZH: "设置"},
	"overview":        {ZH: "概览"},
	"core_status":     {ZH: "内核状态"},
	"current_profile": {ZH: "当前配置"},
	"system_proxy":    {ZH: "系统代理"},
	"running":         {ZH: "运行中"},
	"stopped":         {ZH: "未运行"},
	"enabled":         {ZH: "已开启"},
	"disabled":        {ZH: "已关闭"},
	"traffic":         {ZH: "实时流量"},
	"download":        {ZH: "下载"},
	"upload":          {ZH: "上传"},
	"active_conns":    {ZH: "活跃连接"},
	"quick_settings":  {ZH: "快速设置"},
	"mode":            {ZH: "代理模式"},
	"rule":            {ZH: "规则"},
	"global":          {ZH: "全局"},
	"direct":          {ZH: "直连"},
	"current_node":    {ZH: "当前节点"},
	"import_sub":      {ZH: "导入订阅"},
	"test_delay":      {ZH: "测延迟"},
	"select":          {ZH: "选择"},
	"name":            {ZH: "订阅名称"},
	"url":             {ZH: "订阅地址"},
	"cancel":          {ZH: "取消"},
	"ok":              {ZH: "确定"},
	"error":           {ZH: "错误"},
	"close":           {ZH: "关闭"},
	"save":            {ZH: "保存"},
	"edit":            {ZH: "编辑"},
	"delete":          {ZH: "删除"},
	"update":          {ZH: "更新"},
	"use":             {ZH: "使用"},
	"in_use":          {ZH: "使用中"},
	"refresh":         {ZH: "刷新"},
	"appearance":      {ZH: "外观"},
	"theme":           {ZH: "主题模式"},
	"language":        {ZH: "界面语言"},
	"core":            {ZH: "内核"},
	"restart_core":    {ZH: "重启内核"},
	"backup":          {ZH: "备份"},
	"auto_backup":     {ZH: "立即备份"},
	"about":           {ZH: "关于"},
	"check_update":    {ZH: "检查更新"},
	"yes":             {ZH: "是"},
	"no":              {ZH: "否"},
	"无":               {ZH: "无"},
}

// T 返回 msgid 对应的中文文案，未登记时原样返回。
func T(lang Lang, msgid string) string {
	if m, ok := dict[msgid]; ok {
		return m[ZH]
	}
	return msgid
}

// TByZH 固定返回中文原文（项目只用中文）。
func TByZH(lang Lang, zh string) string { return zh }
