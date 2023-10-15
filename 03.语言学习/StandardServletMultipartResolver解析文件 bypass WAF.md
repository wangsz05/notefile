说明：此篇主要记录学习过程中遇到的问题



# 说明
此篇主要转载自tkswifty师傅，原文链接：[文章地址](https://www.sec-in.com/article/1591)

# 使用场景说明
该技巧可以针对WAF进行绕过，
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/ee4eee16b58758d4882e8ba5e514ebe5.png)

但是经过MultipartFile 取对应的getOriginalFilename 可以取到真正的名称，因为建议在crontroller 在做相关的校验
![image.png](http://moonsec.top/articlepic/33904c385c613f39eef08aa0d947f82b.png)

## 1 文件上传简介
&emsp;&emsp;在JavaWeb应用中，任意文件上传一直是关注的重点，攻击者通过上传恶意jsp文件，可以获取服务器权限。作为Java生态中最常使用的Spring框架，在进行文件上传解析时主要是这两个解析器：
- CommonsMultipartResolver（主要是基于Apache commons fileupload库）
- StandardServletMultipartResolver
CommonsMultipartResolver有很多师傅都分析过了，也有了很多有意思的trick。
&emsp;&emsp;例如在killer师傅提到了在 filename= 1.jsp  的filename字符左右可以加上⼀些空⽩字符 %20%09 %0a %0b %0c %0d %1c %1d %1e %1f ，导致waf匹配不到我们上传⽂件名，⽽我们上传依然可以解析，达到绕过检测的效果。再者还有师傅提到了使用QP编码进行处理，如将测试.jsp进行QP编码处理后为=?UTF-8?Q?=E6=B5=8B=E8=AF=95=2Ejsp?=来达到绕过的效果。

&emsp;&emsp;本文主要围绕另一个解析器StandardServletMultipartResolver，看看有没有什么bypass waf的思路。测试代码如下：
```java
    @PostMapping(path = "/FileUpload")
    public String log4j(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return "上传失败，请选择文件";
        }

        String fileName = file.getOriginalFilename();
        String filePath = "/tmp/";
        File dest = new File(filePath + fileName);
        try {
            file.transferTo(dest);
            return "上传成功,fileName:"+file.getOriginalFilename();
        } catch ( IOException e) {

        }
        return "上传失败！";
    }

```
## 2 StandardServletMultipartResolver解析

&emsp;&emsp;对于一个正常的waf来说，最常见的思路是截取到filename=file_name.jsp，发现扩展名为jsp，接着进行拦截，那么目标很明确，那就是waf解析出的filename不出现jsp关键字，并且后端程序在验证扩展名的时候会认为这是一个jsp文件。

&emsp;&emsp;filename参数一般出现在Content-Dispostion：

```java 
Content-Disposition: form-data; name="key"; filename="file.jsp"
```
&emsp;&emsp;这里主要看看StandardServletMulipartResolver是怎么解析Content-Dispostion的。由于Spring4.x与Spring5.x的代码不一致，这里分别进行分析。StandardServletMultipartResolver中关键multipart请求的解析方法org.springframework.web.multipart.support.StandardMultipartHttpServletRequest.parseRequest，这个是一致的：

## 3 Spring 4.x
&emsp;&emsp;关键multipart请求的解析方法parseRequest：(spring-web-4.3.30.RELEASE)，主要是在extractFilename进行文件名的获取，如果获取不到filename的话则调用extractFilenameWithCharset()进行filename的获取：
```java
private void parseRequest(HttpServletRequest request) {
        try {
            Collection<Part> parts = request.getParts();
            this.multipartParameterNames = new LinkedHashSet<String>(parts.size());
            MultiValueMap<String, MultipartFile> files = new LinkedMultiValueMap<String, MultipartFile>(parts.size());
            for (Part part : parts) {
                String disposition = part.getHeader(CONTENT_DISPOSITION);
                String filename = extractFilename(disposition);
                if (filename == null) {
                    filename = extractFilenameWithCharset(disposition);
                }
                if (filename != null) {
                    files.add(part.getName(), new StandardMultipartFile(part, filename));
                }
                else {
                    this.multipartParameterNames.add(part.getName());
                }
            }
            setMultipartFiles(files);
        }
        catch (Throwable ex) {
            throw new MultipartException("Could not parse multipart servlet request", ex);
        }
    }

```
extractFilename主要是进行substring的切割：
```java
private static final String FILENAME_WITH_CHARSET_KEY =  filename*= ;
private String extractFilenameWithCharset(String contentDisposition) {
        String filename = extractFilename(contentDisposition, FILENAME_WITH_CHARSET_KEY);
        if (filename == null) {
            return null;
        }
        ......
        return filename;
    }

```

## 4 Spring 5.x
&emsp;&emsp;关键multipart请求的解析方法parseRequest(spring-web-5.3.16)，主要的解析方法在org.springframework.http.ContentDisposition的parse方法,在这里对相关的http内容进行了处理：
```java
private void parseRequest(HttpServletRequest request) {
        try {
            Collection<Part> parts = request.getParts();
            this.multipartParameterNames = new LinkedHashSet<>(parts.size());
            MultiValueMap<String, MultipartFile> files = new LinkedMultiValueMap<>(parts.size());
            for (Part part : parts) {
                String headerValue = part.getHeader(HttpHeaders.CONTENT_DISPOSITION);
                ContentDisposition disposition = ContentDisposition.parse(headerValue);
                String filename = disposition.getFilename();
                if (filename != null) {
                    if (filename.startsWith("=?") && filename.endsWith("?=")) {
                        filename = MimeDelegate.decode(filename);
                    }
                    files.add(part.getName(), new StandardMultipartFile(part, filename));
                }
                else {
                    this.multipartParameterNames.add(part.getName());
                }
            }
            setMultipartFiles(files);
        }
        catch (Throwable ex) {
            handleParseFailure(ex);
        }
    }

```
定位到具体的解析方法后，看看具体的解析方式，看看有什么waf bypass的思路。
**filename*=解析**
  参考https://datatracker.ietf.org/doc/html/rfc6266 4.3小节：
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/d0e5d6423f1810b8e93dfa4708e60216.png)

&emsp;&emsp;按照 RFC标准，在 filename 和 filename* 同时出现的情况下，按照 RFC应当忽略 **filename=**，解析**filename*=**，并且会解析如下编码格式(=后面是编码方式，再接着是两个单引号，再接着是使用前面指定编码编码后的文件名)：

```java
Content-Disposition: attachment; filename*= UTF-8''1.jsp
```

  StandardServletMultipartResolver实现了这一个标准，分别查看4.x和5.x的具体实现。
- Spring4.x处理方式
  前面提到了extractFilenameWithCharset()主要是对filename*=参数进行处理：
```java
private String extractFilenameWithCharset(String contentDisposition) {
        String filename = extractFilename(contentDisposition, FILENAME_WITH_CHARSET_KEY);
        if (filename == null) {
            return null;
        }
        int index = filename.indexOf( ' );
        if (index != -1) {
            Charset charset = null;
            try {
                charset = Charset.forName(filename.substring(0, index));
            }
            catch (IllegalArgumentException ex) {
                // ignore
            }
            filename = filename.substring(index + 1);
            // Skip language information..
            index = filename.indexOf( ' );
            if (index != -1) {
                filename = filename.substring(index + 1);
            }
            if (charset != null) {
                filename = new String(filename.getBytes(US_ASCII), charset);
            }
        }
        return filename;
    }

```
&emsp;&emsp;获取到filename*=后的内容后，首先切割第一个'，通过Charset获取对应的编码方式，然后再切割第二个' 后的内容，并根据前面的编码方式进行解码操作，最后返回对应的filename。可以看到实际上两个' 之间是可以任意填充内容的（单引号之间的内容在实际解析时会被忽略掉）:
![image.png](http://moonsec.top/articlepic/90779ddc421406a7bbbd802b0e0ec6b2.png)
# 5 Spring5.x处理方式
- Spring5.x处理方式
  与Spring4的方式类似，对于filename*=的内容，例如传入的==UTF-8'aaa'1.jsp==会被解析成UTF-8编码，最终的文件名为==1.jsp==，而aaa则会被丢弃,主要在ContentDisposition.parse方法进行解析：
```java
else if (attribute.equals("filename*") ) {
                    int idx1 = value.indexOf('\'');
                    int idx2 = value.indexOf('\'', idx1 + 1);
                    if (idx1 != -1 && idx2 != -1) {
                        charset = Charset.forName(value.substring(0, idx1).trim());
                        Assert.isTrue(UTF_8.equals(charset) || ISO_8859_1.equals(charset),
                                "Charset should be UTF-8 or ISO-8859-1");
                        filename = decodeFilename(value.substring(idx2 + 1), charset);
                    }
                    else {
                        // US ASCII
                        filename = decodeFilename(value, StandardCharsets.US_ASCII);
                    }
                }

```

调试过程：
文件上传
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/89c5eb3cc5bfd32b0e95f10415982221.png)
对应的调试代码过程
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/b0e4a47d27c7d9d4ba7c19f8a4ce49cc.png)


- MIME编码
  MIME定义了两种编码方法，其中一种是BASE64，另一种是Quote-Printable，即QP编码。在Spring的MultipartResolver中也有对应的实现。

- QP编码
  前面提到了CommonsMultipartResolver可以使用QP编码进行处理，如将测试.jsp进行QP编码处理后为=?UTF-8?Q?=E6=B5=8B=E8=AF=95=2Ejsp?=来达到绕过的效果。

&emsp;&emsp;对于StandardMultipartHttpServletRequest解析器，在Spring 5.x实现了QP解码，若解析时文件名是=?开始?=结尾，会调用javax.mail库的MimeDelegate解析QP编码，但是要注意的是，javax.mail 库不是 JDK 自带的，必须自行引包，如果不存在该包也将无法解析 ：
```java
if (filename != null) {
    if (filename.startsWith( =? ) && filename.endsWith( ?= )) {
        filename = MimeDelegate.decode(filename);
    }
    files.add(part.getName(), new StandardMultipartFile(part, filename));
}

```
- BASE64编码
  从spring-web-5.3.4开始，在ContentDisposition.parse方法中进行了实现。在解析filename的时候多了一个正则处理：

```java
private final static Pattern BASE64_ENCODED_PATTERN =
Pattern.compile( =\\?([0-9a-zA-Z-_]+)\\?B\\?([+/0-9a-zA-Z]+=*)\\?= );
```
具体代码如下：

  当filename的值以=?开头时，会进入BASE64_ENCODED_PATTERN的正则匹配中，大致的可以知道需要匹配的内容应该是=?编码方式?B?编码内容?= ：
```java
else if (attribute.equals( filename ) && (filename == null)) {
                    if (value.startsWith( =? ) ) {
                        Matcher matcher = BASE64_ENCODED_PATTERN.matcher(value);
                        if (matcher.find()) {
                            String match1 = matcher.group(1);
                            String match2 = matcher.group(2);
                            filename = new String(Base64.getDecoder().decode(match2), Charset.forName(match1));
                        }
                        else {
                            filename = value;
                        }
                    }
                    else {
                        filename = value;
                    }
                }


```
  例如1.jsp经过上述处理后如下：

```java
name= content ;filename= =?utf-8?B?MS5qc3A=?= 
```
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/df257bcdacd0aa216756286cc2f95d87.png)
可以看到整个filename里不包含jsp等关键字，并且成功上传文件。

&emsp;&emsp;综上，在使用StandardServletMultipartResolver进行上传解析时，可以通过相应的编码来尝试进行waf bypass。

# 说明
该技巧可以针对WAF进行绕过，
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/ee4eee16b58758d4882e8ba5e514ebe5.png)

但是经过MultipartFile 取对应的getOriginalFilename 可以取到真正的名称，因为建议在crontroller 在做相关的校验
![image.png](http://moonsec.top/articlepic/33904c385c613f39eef08aa0d947f82b.png)



# 参考
1、https://www.sec-in.com/article/1591