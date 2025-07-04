# 天翼云盘自动签到 + 抽奖 测试
> 天翼云盘自动签到 + 抽奖 OK

***源代码来自：https://51.ruyo.net/16050.html，仅做了一些修改***

**fork自: https://github.com/t00t00-crypto/cloud189-action ,为清理提交历史删掉了仓库重新上传...**

## Github Actions 部署指南

### 一、Fork 此仓库
![image-20200727142541791](https://i.loli.net/2020/07/27/jK5H8FLvt7aBeYX.png)



### 二、设置账号密码
添加名为 **USER**、**PWD** 的变量，值分别为 **账号（仅支持手机号）**、**密码 **

> Settings-->Secrets-->New secret

![image-20200727142753175](https://i.loli.net/2020/07/27/xjri3p4qdchaf2G.png)支持多账号，账号之间与密码之间用 ***换行*** 分隔，账号与密码的个数要对应

示例：（本地md中已经是“换行“分隔，但github上显示空格分隔。囧，记得换行分隔。记得换行分隔。记得换行分隔）

**USER**

>13800000000
13800000001

**PWD**

>123456
123123


如果有需要报错时消息推送，可以自行新增**PUSH_TOKEN**、**BOT_TOKEN** 、**CHAT_ID**的变量，值分别为 **PUSHPLUS微信推送token**、**TG机器人token **、**TG聊天id**
（预留了两个方式推送，选择PUSHPLUS或者tg之一即可。）



### 三、启用 Action
1. 点击 ***Actions***，再点击 **I understand my workflows, go ahead and enable them**

   ![](https://i.loli.net/2020/07/27/pyQmdMHrOIz4x2f.png)

2. 点击左侧的 ***Star*** 手动启动

   ![image-20200727142617807](https://i.loli.net/2020/07/27/3cXnHYIbOxfQDZh.png)

### 四、查看运行结果
> Actions --> 签到 --> build

能看到如下图所示，表示成功

![image-20200727144951950](https://i.loli.net/2020/07/27/VbrHu8UJXiIkqGx.png)

## 注意事项

1. 每天运行两次，在上午 6 点和 10 点30。

2. 可以通过 ***Star*** 手动启动一次。
3. 多个账号、密码用换行分隔
4. rum.yaml中cron表达式对应时间不是北京时间东八区，而是慢8小时的UTC

   ![image-20200727142617807](https://i.loli.net/2020/07/27/87oQeLJOlZvU3Ep.png)
