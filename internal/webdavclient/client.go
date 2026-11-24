// Package webdavclient 是纯标准库的 WebDAV 客户端（PROPFIND/MKCOL/PUT/GET/DELETE）。
package webdavclient

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

// Client 是一个 WebDAV 客户端。
type Client struct {
	base     string
	username string
	password string
	http     *http.Client
}

// NewClient 创建客户端（Base URL 形如 https://dav.example.com/path）。
func NewClient(base, username, password string) *Client {
	return &Client{
		base:     strings.TrimRight(base, "/"),
		username: username,
		password: password,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
}

// Connect 验证端点可达（发一个根目录 PROPFIND）。
func (c *Client) Connect() error {
	_, err := c.propfind("/")
	return err
}

func (c *Client) do(method, p string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, c.base+p, body)
	if err != nil {
		return nil, err
	}
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	return c.http.Do(req)
}

// File 描述一个 WebDAV 资源。
type File struct {
	Href         string
	Name         string
	IsDir        bool
	Size         int64
	LastModified time.Time
}

// propfind 解析 WebDAV multistatus XML。
type multistatus struct {
	XMLName   xml.Name `xml:"multistatus"`
	Responses []struct {
		Href  string `xml:"href"`
		Props struct {
			ResType struct {
				Collection *struct{} `xml:"collection"`
			} `xml:"resourcetype"`
			ContentLength string `xml:"getcontentlength"`
			LastModified  string `xml:"getlastmodified"`
		} `xml:"propstat>prop"`
	} `xml:"response"`
}

func (c *Client) propfind(p string) (*multistatus, error) {
	body := `<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:"><d:prop>
  <d:resourcetype/><d:getcontentlength/><d:getlastmodified/>
</d:prop></d:propfind>`
	req, err := http.NewRequest("PROPFIND", c.base+p, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	req.Header.Set("Depth", "1")
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("PROPFIND %s: HTTP %d", p, resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)
	var ms multistatus
	if err := xml.Unmarshal(data, &ms); err != nil {
		// 某些服务端返回空 body（如根 PROPFIND 仅探活）。
		return &multistatus{}, nil
	}
	return &ms, nil
}

// ReadDir 列出目录内容（只返回直接子项）。
func (c *Client) ReadDir(p string) ([]File, error) {
	ms, err := c.propfind(p)
	if err != nil {
		return nil, err
	}
	baseHref, _ := url.PathUnescape(ms.Responses[0].Href)
	var out []File
	for _, r := range ms.Responses {
		href, _ := url.PathUnescape(r.Href)
		if href == baseHref {
			continue
		}
		name := path.Base(strings.TrimRight(href, "/"))
		isDir := r.Props.ResType.Collection != nil
		var size int64
		fmt.Sscanf(r.Props.ContentLength, "%d", &size)
		var mod time.Time
		if r.Props.LastModified != "" {
			if t, e := http.ParseTime(r.Props.LastModified); e == nil {
				mod = t
			}
		}
		out = append(out, File{Href: href, Name: name, IsDir: isDir, Size: size, LastModified: mod})
	}
	return out, nil
}

// MkdirAll 递归创建目录。
func (c *Client) MkdirAll(p string, perm os.FileMode) error {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	cur := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		cur += "/" + part
		req, err := http.NewRequest("MKCOL", c.base+cur, nil)
		if err != nil {
			return err
		}
		if c.username != "" || c.password != "" {
			req.SetBasicAuth(c.username, c.password)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		// 405 表示已存在，视为成功。
		if resp.StatusCode != 201 && resp.StatusCode != 405 && resp.StatusCode != 204 {
			return fmt.Errorf("MKCOL %s: HTTP %d", cur, resp.StatusCode)
		}
	}
	return nil
}

// Write 上传文件。
func (c *Client) Write(p string, data []byte, perm os.FileMode) error {
	resp, err := c.do("PUT", p, bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("PUT %s: HTTP %d", p, resp.StatusCode)
	}
	return nil
}

// Read 下载文件。
func (c *Client) Read(p string) ([]byte, error) {
	resp, err := c.do("GET", p, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s: HTTP %d", p, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// RemoveAll 删除资源。
func (c *Client) RemoveAll(p string) error {
	resp, err := c.do("DELETE", p, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 204 && resp.StatusCode != 200 && resp.StatusCode != 404 {
		return fmt.Errorf("DELETE %s: HTTP %d", p, resp.StatusCode)
	}
	return nil
}
