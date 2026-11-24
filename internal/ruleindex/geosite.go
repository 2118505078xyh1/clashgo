package ruleindex

import (
	"strings"
	"sync"
)

// geositeData 内置域名分类（覆盖常见国内/国外/广告域名分类）。
// 这是精简但实用的数据集；完整 geosite.dat 需外部数据文件，与零依赖目标冲突。
var geositeData = map[string][]string{
	"geolocation-cn": {
		"baidu.com", "qq.com", "taobao.com", "jd.com", "bilibili.com", "163.com",
		"weibo.com", "aliyun.com", "cn", "sina.com", "sohu.com", "360.cn",
		"xiaomi.com", "huawei.com", "mi.com", "tencent.com", "alipay.com",
		"douyin.com", "toutiao.com", "kuaishou.com", "meituan.com", "dianping.com",
		"zhihu.com", "csdn.net", "bilibili.tv", "126.com", "139.com", "189.cn",
		"gov.cn", "edu.cn", "ac.cn", "org.cn", "net.cn", "com.cn",
	},
	"geolocation-!cn": {
		"google.com", "youtube.com", "facebook.com", "twitter.com", "github.com",
		"openai.com", "instagram.com", "linkedin.com", "tiktok.com", "netflix.com",
		"spotify.com", "amazon.com", "microsoft.com", "apple.com", "cloudflare.com",
		"wikipedia.org", "reddit.com", "telegram.org", "whatsapp.com", "discord.com",
		"twitch.tv", "hulu.com", "hbo.com", "disneyplus.com", "bbc.com", "cnn.com",
		"nytimes.com", "theguardian.com", "bbc.co.uk", "vk.com", "yandex.ru",
	},
	"category-ads-all": {
		"doubleclick.net", "googleadservices.com", "googlesyndication.com",
		"adservice.google.com", "ads.youtube.com", "ad.doubleclick.net",
		"google-analytics.com", "googletagmanager.com", "facebook.net",
		"connect.facebook.net", "scorecardresearch.com", "quantserve.com",
		"amazon-adsystem.com", "adnxs.com", "criteo.com", "taboola.com",
		"outbrain.com", "pubmatic.com", "rubiconproject.com", "openx.net",
		"adcolony.com", "unityads.unity3d.com", "vungle.com", "applovin.com",
	},
	"category-ads": {
		"doubleclick.net", "googleadservices.com", "googlesyndication.com",
		"adservice.google.com", "google-analytics.com", "googletagmanager.com",
	},
	"private": {
		"localhost", "local", "internal", "lan", "localdomain", "arpa",
	},
}

var geositeCache sync.Map // map[string][]string（返回副本）

// GeoSiteDomains 返回指定分类的域名列表（大小写不敏感，返回副本防止外部修改）。
func GeoSiteDomains(category string) []string {
	key := strings.ToLower(strings.TrimSpace(category))
	if cached, ok := geositeCache.Load(key); ok {
		return append([]string(nil), cached.([]string)...)
	}
	domains, ok := geositeData[key]
	if !ok {
		return nil
	}
	geositeCache.Store(key, domains)
	return append([]string(nil), domains...)
}
