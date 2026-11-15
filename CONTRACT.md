# 离线更正包的批前旧像应用

本题定义自己的有限格式，非完整SQLite原生changeset，不要求兼容其串行冲突策略。仅一个items表：(id INTEGER PRIMARY KEY, tag TEXT NULL, payload BLOB NULL)。id为有符号64位非布尔整数，tag为严格UTF-8文本或None，payload为bytes或None。没有外键、触发器、其他表业务、Schema演进、冲突自动合并、并发写入或网络。

实现changeimport.py。Decoder(chunks)为单次操作可迭代源；chunks是一次性bytes块，每块0..65536字节。Store(path)创建或打开SQLite库。seed(rows)仅用于空库初始化，rows为合法(id,tag,payload)迭代器，seed整次原子；read(id)->(id,tag,payload)或None，供小规模验证；summary()->[(id,tag,payload_size_or_None,payload_sha256_or_None)]按id升序，items中的None不同于空bytes。Store.apply(operations)->{'inserted':n,'updated':n,'deleted':n}，operations可以是Decoder，也可以第三方操作源。Store.close()关闭。拒绝时抛ValueError，输入源异常原样传播，已有库保持旧状态；允许处理后继续使用Store。

包头固定b'CHG1'，其后操作序列，最后一个字节0x00标识结束，其后必须EOF；不能只看到结束标记就提交而不读完源。操作0x12插入含一组新行，0x09删除含一组旧行，0x17更新含旧行及新行；行固定三字段。字段标记0为UNSET，1为后接8字节大端有符号整数，3为后接uvar长度及该字节数UTF-8文本，4为后接uvar长度及原始bytes，5为NULL；其余标记拒绝。uvar使用最短无符号LEB128，最多9字节且值不超过2**63-1，非最短表示拒绝。id只允许整数或UNSET，tag只允许文本、NULL或UNSET，payload只允许bytes、NULL或UNSET。

插入三个字段都不可UNSET，id不得NULL。删除旧id必须给出，tag/payload可UNSET，仅已给出的旧字段参与核对；更新旧id必须给出，新id可UNSET表不改；更新任一新tag/payload若给出，则对应旧字段必须给出，反之旧字段可另给作校验；新行全UNSET属于合法无变化更新。旧字段比较须类型和值相等，不得把UNSET转成None或空bytes。输入合法性与冲突均不能留下部分更改。

操作公开表示为事件而非整条大bytes：begin含seq（0起连续）、op='insert'/'delete'/'update'；field含seq,side='old'/'new',column='id'/'tag'/'payload',kind='unset'/'null'/'int'/'text'/'blob',length；int事件另有value，length=0；text/blob的length为编码字节数，随后0至多条data事件含seq、data:bytes；field_end含seq；end含seq。side/column的出现顺序严格按上述操作的旧行后新行、各行id/tag/payload；每个field恰有field_end，text/blob data累计等于length，每data<=65536，text须严格UTF-8且可跨data截断多字节字符。所有值均可只给field然后field_end表示空文本/空blob。unset/null length=0且没有data。begin至end不交错操作；事件不能含额外字段替代缺失的合法字段。Decoder必须自行校验字节格式与行类型，Store仍独立校验事件次序、类型及长度，不访问Decoder私有状态。

整个包涉及的所有delete/update旧id互不重复，否则拒绝，不允许用后条操作读取前条新值。每个delete/update须在批前库找到旧id且匹配所有已提供旧字段；更新结果为其批前原行叠加所有提供的新值。insert和update最终id必须彼此唯一，并且不能占用未被本批delete/update移走的批前记录id；原id不变的update保留自身位置也合法。delete/update所占旧id整体先从最终键空间释放，再考虑全部insert/update结果，是否可用由最终映射决定，与操作输入顺序无关。

例批前(1,'A',b'x'),(2,'B',b'y')：update旧(1,'A',UNSET)、新(2,'AA',UNSET)，以及update旧(2,UNSET,UNSET)、新(1,UNSET,UNSET)，成功得(1,'B',b'y'),(2,'AA',b'x')。只做第一条则冲突且原库不变。delete旧id1与insert新(1,None,b'')可以同批成功。更新把tag给NULL必须真的置NULL，payload UNSET仍保留原值。

大text/blob不能整个保存在Python内存；事件输入及临时载荷全程额外值载荷内存至多8MiB，不能通过先合并事件/全包字符串规避。允许随记录数增长的固定元数据和SQLite暂存、私有顺序文件或BLOB增量I/O；标准SQLite是合法复用，不要求自建事务引擎。summary结果、调用方本来持有的单个data块不计正文预算；read只用于小数据核验，不用于大正文内部比较。旧像和重建正文比较必须逐字节等价，不能仅信任长度；可以先摘要筛选再完整核对。

apply只有完整消费结束且全部校验成功才向主items提交，失败不能损坏任何批前记录；单进程串行，不要求与其他进程同时写。进程在apply中任意时刻SIGKILL后，重开库必须是完整批前或完整批后，不能半批，未提交自有暂存可在重开清理，不能删无关文件；不模拟磁盘掉电或SQLite损坏。计数按操作数量，无变化update也算updated一次。

verify用独立字节构造和完整小规模批前参照，核对字段未提供/NULL/空值、主键交换、delete腾位、冲突保全、尾部坏字节、逐字节切分和第三方事件源；大正文用生成流核对摘要、内存峰值与源消费次数。真实子进程在操作中途被杀并重开核账；报告区分已实测中断点与依赖SQLite事务保证的语义结论。
交付.pointwise-runtime.json：version=1、kind=cli，setup为准备命令argv数组列表，verify/demo为执行真实业务核验及演示的argv数组。原fixture_check.py只检查公开材料，不能作为目标业务核验。
