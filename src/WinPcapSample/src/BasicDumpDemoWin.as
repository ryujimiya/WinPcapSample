package
{
    import flash.events.Event;
    import flash.events.MouseEvent;
    import flash.events.TimerEvent;
    import flash.utils.ByteArray;
    import flash.utils.getQualifiedClassName;
    import flash.utils.Timer;
    import livefan.packet.IpPacket;
    import livefan.packet.Ipv4Packet;
    import livefan.packet.Ipv6Packet;
    import livefan.packet.Packet;
    import livefan.packet.PacketUtil;
    import livefan.packet.TcpPacket;
    import livefan.packet.UdpPacket;
    import livefan.winpcap.PcapAddr;
    import livefan.winpcap.PcapDefine;
    import livefan.winpcap.PcapDumper;
    import livefan.winpcap.PcapHandle;
    import livefan.winpcap.PcapIf;
    import livefan.winpcap.PcapPktHdr;
    import livefan.winpcap.PcapStat;
    import livefan.winpcap.ResultAllDevs;
    import livefan.winpcap.ResultGetArrival;
    import livefan.winpcap.ResultPcap;
    import livefan.winpcap.ResultPcapDump;
    import livefan.winpcap.ResultPcapNext;
    import livefan.winpcap.ResultPcapStats;
    import livefan.winpcap.SockAddr;
    import livefan.winpcap.Timeval;
    import livefan.winpcap.WinPcapExtension;
    import livefan.winpcap.WinPcapExtensionEvent;
    import mx.collections.ArrayCollection;
    import mx.controls.Alert;
    import mx.events.AIREvent;
    import mx.events.ItemClickEvent;
    import mx.utils.StringUtil;
    import spark.events.IndexChangeEvent;
    
    /**
     *
     * @author Owner
     */
    public class BasicDumpDemoWin extends BasicDumpDemoWinView
    {
        /**
         * タイマーイベント毎に取得するパケット数(pcapNextEx使用時)
         */
        private static const MaxPacketCntToGet:int = 10000;

        /**
         * WinPcapネイティブ拡張インスタンス
         */
        private var _extension:WinPcapExtension = null;
        /**
         * ネットワークインターフェースインスタンス
         */
        private var _pcapIf:PcapIf = null;
        /**
         * WinPcapハンドル
         */
        private var _pcapHandle:PcapHandle = null;
        /**
         * ダンプファイルハンドル
         */
        private var _pcapDumper:PcapDumper = null;
        /**
         * CaptureThreadを使用する?
         * true: CaptureThread  false: pcapNextEx
         */
        private var _useCaptureThread:Boolean = false;
        /**
         * タイマー(pcapNextEx使用時)
         */
        private var _timer:Timer = null;
        /**
         * タイマー処理中?(pcapNext使用時)
         */
        private var _timerProcRunning:Boolean = false;
        /**
         * GUI更新タイマー(CaptureThread使用時)
         */
        private var _guiUpdateTimer:Timer = null;
        /**
         * ダンプデータ表示用テキストエリアの表示テキストのリスト(CaptureThread使用時でファイル読み込みの場合
         */
        private var _textAreaDumpTextList:Vector.<String> = new Vector.<String>();
        
        /**
         * コンストラクタ
         */
        public function BasicDumpDemoWin()
        {
            super();
            addEventListener(AIREvent.WINDOW_COMPLETE, initWin);
            addEventListener(Event.CLOSING, closing);
        }
        
        /**
         * ウィンドウが初期化された
         * @param e
         */
        private function initWin(e:AIREvent):void 
        {
            // WinPcap拡張インスタンスの生成
            _extension = new WinPcapExtension();
            _extension.addEventListener(WinPcapExtensionEvent.CAPTURETHREAD_PACKETARRIVAL, onCaptureThreadPacketArrival);
            _extension.addEventListener(WinPcapExtensionEvent.CAPTURETHREAD_THREADFUNCFINISHED, onCaptureThreadFinished);

            radioCapThread.value = "radioCapThread";
            radioPcapNext.value = "radioPcapNext";
            radioGroupMethodArrival.selectedValue = _useCaptureThread? radioCapThread.value : radioPcapNext.value;
            textAreaNetworkIf.editable = false;
            textAreaDump.editable = false;

            btnSrcStrApply.addEventListener(MouseEvent.CLICK, btnSrcStrApplyClick);
            listNetworkIf.addEventListener(IndexChangeEvent.CHANGE, listNetworkIfIndexChange);
            radioGroupMethodArrival.addEventListener(ItemClickEvent.ITEM_CLICK, radioGroupMethodArrivalItemClick);
            btnStart.addEventListener(MouseEvent.CLICK, btnStartClick);

            // libpcapのダンプファイルバージョン
            var versionStr:String = _extension.pcapLibVersion();
            labelVersion.text = "libcap version: " + versionStr;

            var textForLabelSrcStr:String = "";
            var newlineStr:String = "\r\n";
            textForLabelSrcStr = "Enter the device you want to list:" + newlineStr
                 + "syntax:" + newlineStr
                 + "    rpcap://    rpcap://hostname:port    file://foldername" + newlineStr;
            labelSrcStr.text = textForLabelSrcStr;

            setupNetworkIfList();
        }
        
        /**
         * ウィンドウが閉じられようとしている
         * @param e
         */
        private function closing(e:Event):void 
        {
            stopCapture();
            _extension.dispose();
        }

        /**
         * パケットが到達した(CaptureThread使用時)
         * @param e
         */
        private function onCaptureThreadPacketArrival(e:WinPcapExtensionEvent):void 
        {
            if (_pcapHandle == null)
            {
                return;
            }
            getCapturedData();
        }
        
        /**
         * キャプチャースレッドが終了した(CaptureThread使用時)
         * @param e
         */
        private function onCaptureThreadFinished(e:WinPcapExtensionEvent):void
        {
            if (_pcapHandle != null)
            {
                Alert.show("CaptureThread was finished by itself. (maybe EOF was detected)", "", Alert.OK, this);
                if (_textAreaDumpTextList.length > 0)
                {
                    // GUI更新中の場合
                    // キャプチャーを終了するが、[Stop]ボタンは[Start]に変更しないようにするため、stopCaptureを直接呼び出す
                    stopCapture();
                }
                else
                {
                    // キャプチャー終了済みでない場合、stopCaptureを呼び出すために
                    // [Stop]ボタンクリックイベントを疑似送信する
                    btnStart.dispatchEvent(new MouseEvent(MouseEvent.CLICK));
                }
            }
            else
            {
                // stopCaptureを呼び出した場合は、このイベント到達時には終了処理済み
            }
        }

        /**
         * [Apply]ボタン(sourceの反映)がクリックされた
         * @param e
         */
        private function btnSrcStrApplyClick(e:MouseEvent):void 
        {
            setupNetworkIfList();
        }
		
		/**
		 * ソースの取得
		 * @return
		 */
		private function getSourceFromGui():String
		{
            var source:String = "";
            source = textInputSrcStr.text;
            source = StringUtil.trim(source);
            if (source.length == 0)
            {
                source = PcapDefine.PCAP_SRC_IF_STRING;
            }
			return source;
		}

        /**
         * ネットワークインターフェース一覧をセットアップ
         */
        private function setupNetworkIfList():void
        {
            if (_pcapHandle != null)
            {
                return;
            }
			var source:String = getSourceFromGui();
            var isReadFile:Boolean = (source.indexOf(PcapDefine.PCAP_SRC_FILE_STRING) == 0);
            if (isReadFile)
            {
                // dumpファイルを無効にする
                textInputDumpFilename.text = "";
                textInputDumpFilename.enabled = false;
            }
            else
            {
                textInputDumpFilename.enabled = true;
            }
            
            var oldDataProdiver:ArrayCollection = listNetworkIf.dataProvider as ArrayCollection;
            if (oldDataProdiver != null)
            {
                oldDataProdiver.removeAll();
                listNetworkIf.dataProvider = null;
                textAreaNetworkIf.text = "";
            }
            
            // ネットワークインターフェースの一覧を取得
            var resAllDevs:ResultAllDevs = _extension.pcapFindAllDevsEx(source, null);
            if (resAllDevs.retVal != 0)
            {
                Alert.show(resAllDevs.errBuf, "", Alert.OK, this);
                return;
            }
            
            // ネットワークインターフェースをリストに登録
            var dataProvider:ArrayCollection = new ArrayCollection();
            var pcapIfs:PcapIf = resAllDevs.pcapIfs;
            for (var pcapIf:PcapIf = pcapIfs; pcapIf != null; pcapIf = pcapIf.next)
            {
                var name:String = pcapIf.name;
                var description:String = pcapIf.description;
                var addresses:PcapAddr = pcapIf.addresses;
                var labelStr:String = description;
                dataProvider.addItem( { label: labelStr , data:pcapIf } );
            }
            listNetworkIf.dataProvider = dataProvider;
            
            // インターフェース一覧を解放
            resAllDevs.dispose();
        }

        /**
         * ネットワークインターフェース一覧リストの選択しているインデックスが変わった
         * @param e
         */
        private function listNetworkIfIndexChange(e:IndexChangeEvent):void 
        {
            if (e.newIndex == -1)
            {
                return;
            }
            var dataProvider:ArrayCollection = listNetworkIf.dataProvider as ArrayCollection;
            if (dataProvider == null)
            {
                return;
            }
            var item:Object = dataProvider.getItemAt(e.newIndex);
            if (item == null)
            {
                return;
            }
            var pcapIf:PcapIf = item.data;
            if (pcapIf == null)
            {
                return;
            }
            var name:String = pcapIf.name;
            var description:String = pcapIf.description;
            var addresses:PcapAddr = pcapIf.addresses;
            var flags:uint = pcapIf.flags;
            
            var newlineStr:String = "\r\n";
            var text:String = "";
            text += "name: " + name + newlineStr;
            text += "description: " + description + newlineStr;
            text += "loopback: " + ((flags & PcapDefine.PCAP_IF_LOOPBACK)? "yes":"no") + newlineStr;
            var addressCounter:int = 0;
            for (var addr:PcapAddr = addresses; addr != null; addr = addr.next)
            {
                text += "(" + (addressCounter + 1) + ")" + newlineStr;
                if (addr.addr != null && addr.addr.saFamily != 0)
                {
                    text += "  address: " + newlineStr;
                    text += "    sa family: " + saFamilyStr(addr.addr.saFamily) + newlineStr;
                    text += "    address: " + getGuiStrAddr(_extension, addr.addr) + newlineStr;
                }
                if (addr.netMask != null && addr.netMask.saFamily != 0)
                {
                    text += "  netmask: " + newlineStr;
                    text += "    sa family: " + saFamilyStr(addr.netMask.saFamily) + newlineStr;
                    text += "    address: " + getGuiStrAddr(_extension, addr.netMask) + newlineStr;
                }
                if (addr.broadAddr != null && addr.broadAddr.saFamily != 0)
                {
                    text += "  broad address: " + newlineStr;
                    text += "    sa family: " + saFamilyStr(addr.broadAddr.saFamily) + newlineStr;
                    text += "    address: " + getGuiStrAddr(_extension, addr.broadAddr) + newlineStr;
                }
                if (addr.dstAddr != null && addr.dstAddr.saFamily != 0)
                {
                    text += "  dst address: " + newlineStr;
                    text += "    sa family: " + saFamilyStr(addr.dstAddr.saFamily) + newlineStr;
                    text += "    address: " + getGuiStrAddr(_extension, addr.dstAddr) + newlineStr;
                }
                addressCounter++;
            }
            textAreaNetworkIf.text = text;
        }
        
        /**
         * SockAddrのsaFamily値に対応する文字列を取得する
         * @param saFamily
         * @return
         */
        private static function saFamilyStr(saFamily:uint):String
        {
            if (saFamily == SockAddr.AF_INET)
            {
                return "IPv4";
            }
            else if (saFamily == SockAddr.AF_INET6)
            {
                return "IPv6";
            }
            return saFamily.toString();
        }
        
        /**
         * GUI表示用アドレス文字列を取得する
         * @param extension WinPcapネイティブ拡張インスタンス
         * @param addr ソケットアドレスインスタンス
         * @return
         */
        private static function getGuiStrAddr(extension:WinPcapExtension, addr:SockAddr):String
        {
            var i:int;
            var newlineStr:String = "\r\n";
            var headStr:String = "             ";
            var text:String = "";

            var addrAsBytes:ByteArray = addr.addrAsBytes;
            text = extension.IpAddrByteArrayToString(addr.saFamily, addrAsBytes) + newlineStr;
            text += headStr + "(";
            for (i = 0; i < addrAsBytes.length; i++)
            {
                var val:uint = addrAsBytes[i];
                text += val.toString(16) + " ";
            }
            text += ")";
            return text;
        }
        
        /**
         * [use CaptureThread/ use PcapNextEx]ラジオボタングループのアイテムがクリックされた
         * @param e
         */
        private function radioGroupMethodArrivalItemClick(e:ItemClickEvent):void 
        {
            if (e.currentTarget.selectedValue == radioCapThread.value)
            {
                _useCaptureThread = true;
            }
            else
            {
                _useCaptureThread = false;
            }
        }

        /**
         * [Start]ボタンがクリックされた
         * @param e
         */
        private function btnStartClick(e:MouseEvent):void 
        {            
            if (_pcapHandle == null)
            {
                if (_textAreaDumpTextList.length > 0)
                {
                    // CaptureThread使用時でGUI更新中のときは更新をストップする
                    _textAreaDumpTextList.splice(0, _textAreaDumpTextList.length);
                    return;
                }

                var item:Object = listNetworkIf.selectedItem;
                if (item == null)
                {
                    return;
                }
                _pcapIf = item.data;
                if (_pcapIf == null)
                {
                    return;
                }
                var success:Boolean = startCapture(_pcapIf.name);
                if (!success)
                {
                    return;
                }
                btnStart.label = "Stop";
                radioGroupMethodArrival.enabled = false;
                textAreaDump.text = "";
            }
            else
            {
                stopCapture();
                btnStart.label = "Start";
                radioGroupMethodArrival.enabled = true;
            }
        }
        
        /**
         * キャプチャーを開始する
         * @param adapterName ネットワークアダプタ名(rpcap://, file://で始まる文字列)
         * @return
         */
        private function startCapture(adapterName:String):Boolean
        {
            var resPcap:ResultPcap = _extension.pcapOpen(
                adapterName,
                65535,
                PcapDefine.PCAP_OPENFLAG_PROMISCUOUS,
                20,
                null);
            if (resPcap.retVal != 0)
            {
                Alert.show(resPcap.errBuf, "", Alert.OK, this);
                return false;
            }
            this._pcapHandle = resPcap.pcapHandle;
            setFilter();
            showPcapHandleInfo();
            startDump();
            if (_useCaptureThread)
            {
                this._pcapHandle.startCaptureThread(); // CaptureThreadを起動する
            }
            else
            {
                startTimer();
            }
            trace("startCapture done");
            return true;
        }
        
        /**
         * キャプチャーを終了する
         */
        private function stopCapture():void
        {
            if (_pcapHandle == null)
            {
                return;
            }
            if (_useCaptureThread)
            {
                 _pcapHandle.stopCaptureThread(); // CaptureThreadを終了する
            }
            else
            {
                killTimer();
            }
            stopDump();
            showPcapStaticsInfo();
            _pcapHandle.pcapClose();
            _pcapHandle.dispose();
            _pcapHandle = null;
            trace("stopCapture done");
        }
        
        /**
         * フィルターを設定する
         */
        private function setFilter():void
        {
            var filterStr:String = "";
            var netmask:uint = 0xffffff00; // 255.255.255.0

            if (_pcapHandle == null)
            {
                return;
            }
            
            filterStr = textInputFilter.text;
            filterStr = StringUtil.trim(filterStr);
            if (filterStr.length == 0)
            {
                return;
            }
            var ret:int = _pcapHandle.pcapSetFilter(filterStr, 1, netmask);
        }
        
        /**
         * pcapHandleの情報を表示する
         */
        private function showPcapHandleInfo():void
        {
            var newlineStr:String = "\r\n";
            var text:String = "";
            if (_pcapHandle != null)
            {
                var dlt:int = _pcapHandle.pcapDataLink();
                var dltAry:Array = _pcapHandle.pcapListDataLinks();
                text += "datalink type: " + dlt.toString() + newlineStr;
                text += "datalink type list: ";
                for (var i:int = 0; i < dltAry.length; i++)
                {
                    var val:int = dltAry[i];
                    text += val.toString() + " ";
                }
                text += newlineStr;
            }
            labelPcapHandleInfo.text = text;
        }
        
        private function showPcapStaticsInfo():void
        {
            var newlineStr:String = "\r\n";
            var text:String = "";
            if (_pcapHandle != null)
            {
                var resPcapStats:ResultPcapStats = _pcapHandle.pcapStats();
                var ret:int = resPcapStats.retVal;
                text += "[pcapStats]" + newlineStr;
                if (ret != -1)
                {
                    var stat:PcapStat = resPcapStats.pcapStat;
                    text += "    psRecv: " + stat.psRecv.toString() + newlineStr;
                    text += "    psDrop: " + stat.psDrop.toString() + newlineStr;
                    text += "    psIfdrop: " + stat.psIfDrop.toString() + newlineStr;
                    text += "    psCapt: " + stat.psCapt.toString() + newlineStr;
                    text += "    psSent: " + stat.psSent.toString() + newlineStr;
                    text += "    psNetdrop: " + stat.psNetdrop.toString() + newlineStr;
                }
                else
                {
                    text += "    (not available)" + newlineStr;
                }
            }
            //labelPcapHandleInfo.text = text;
            labelPcapHandleInfo.text += text; // 最後に追加
        }
        
        /**
         * ダンプデータファイル書き込みを開始する
         */
        private function startDump():void
        {
            if (_pcapHandle == null)
            {
                return;
            }
            var fname:String = textInputDumpFilename.text;
            fname = StringUtil.trim(fname);
            if (fname.length > 0)
            {
                var resPcapDump:ResultPcapDump = _pcapHandle.pcapDumpOpen(fname);
                this._pcapDumper = resPcapDump.pcapDumper;
            }
            labelDumpFTell.text = "";
        }
        
        /**
         * ダンプデータファイル書き込みを終了する
         */
        private function stopDump():void
        {
            if (_pcapDumper == null)
            {
                return;
            }
            _pcapDumper.pcapDumpClose();
            _pcapDumper = null;
        }
        
        /**
         * タイマーを起動する(pcapNextEx使用時)
         */
        private function startTimer():void
        {
            _timer = new Timer(50, 0);
            _timer.addEventListener(TimerEvent.TIMER, timerProc);
            _timer.start();
        }
        
        /**
         * タイマーを終了する(pcapNextEx使用時)
         */
        private function killTimer():void
        {
            if (_timer != null)
            {
                _timer.stop();
                _timer.removeEventListener(TimerEvent.TIMER, timerProc);
                _timer = null;
            }
        }
        
        /**
         * タイマーイベントハンドラ(pcapNextEx使用時)
         * @param e
         */
        private function timerProc(e:TimerEvent):void 
        {
            if (_timerProcRunning)
            {
                return;
            }
            _timerProcRunning = true;
            
            var ret:int = 0;
			var source:String = getSourceFromGui();
            var isReadFile:Boolean = (source.indexOf(PcapDefine.PCAP_SRC_FILE_STRING) == 0);
            var maxCnt:int = isReadFile? 1: MaxPacketCntToGet;
            var cnt:int = 0;
            
            while (cnt < maxCnt)
            {
                ret = getCapturedData();
                if (ret != 1)
                {
                    break;
                }
                cnt++;
            }
            
            _timerProcRunning = false;
        }

        /**
         * キャプチャーデータ取得処理
         * @return 1:取得成功 0:タイムアウト -1:エラー -2:pcap_loopから抜けた
         */
        private function getCapturedData():int
        {
            var ret:int = 0;
            if (_useCaptureThread)
            {
                ret = getCaptureDataCapThread();
            }
            else
            {
                ret = getCaptureDataPcapNext();
            }
            return ret;
        }
        
        /**
         * CaptureThread使用時のキャプチャーデータ取得処理
         * @return 1:取得成功 0:タイムアウト -1:エラー -2:pcap_loopから抜けた
         */
        private function getCaptureDataCapThread():int
        {
            if (_pcapHandle == null)
            {
                return -1;
            }
			var packetCnt:int = _pcapHandle.getArrivalPacketCount();
			var ret:int = -1;
			for (var i:int = 0;  i < packetCnt; i++)
			{
                // 到達パケットを取得する
                var resGetArrival:ResultGetArrival = _pcapHandle.getArrivalPacket();
                ret = resGetArrival.retVal;
                var header:PcapPktHdr = resGetArrival.header as PcapPktHdr;
                var data:ByteArray = resGetArrival.data as ByteArray;
            
                // パケットデータをファイルに書き込む
                if (_pcapDumper != null && ret == 1)
                {
                    _pcapDumper.pcapDump(header, data);
                    var retInt:int = _pcapDumper.pcapDumpFlush();
                }
                resGetArrival.dispose(); // 結果を破棄する (取得したheaderはnativeで使用不可となる)
                if (ret != 1)
                {
                    trace("CaptureThread handler: ret = " + ret.toString());
					continue;
                }
            
                // パケットパース処理
                var packetInfoStr:String = parsePacket(data);

                // 表示
                updateGui(data, header, packetInfoStr);
			}

			return ret;
		}
        
        /**
         * pcapNextExを使用する場合のキャプチャーデータ取得処理
         * @return 1:取得成功 0:タイムアウト -1:エラー -2:pcap_loopから抜けた
         */
        private function getCaptureDataPcapNext():int
        {
            if (_pcapHandle == null)
            {
                return -1;
            }
            // パケットデータを取得する
            var resPcapNext:ResultPcapNext = _pcapHandle.pcapNextEx();
            var ret:int = resPcapNext.retVal;
            var header:PcapPktHdr = resPcapNext.header;
            var data:ByteArray = resPcapNext.data;
            if (ret != 1)
            {
                if (ret != 0) // タイムアウト以外
                {
                    trace("pcapNextEx: ret =" + ret.toString());
                }
                if (ret == -2 && _pcapIf.name.indexOf(PcapDefine.PCAP_SRC_FILE_STRING) == 0)
                {
                    // ファイル読み込みで終端を検出したときは、[Stop]ボタンクリックイベントを疑似送信する
                    btnStart.dispatchEvent(new MouseEvent(MouseEvent.CLICK));
                }
                return ret;
            }

            // パケットデータをファイルに書き込む
            //   data.length != header.capLenのときがある(ret != 1の場合)
            if (_pcapDumper != null)
            {
                _pcapDumper.pcapDump(header, data);
                var retInt:int = _pcapDumper.pcapDumpFlush();
            }
            
            // パケットパース処理
            var packetInfoStr:String = parsePacket(data);

            // 表示
            updateGui(data, header, packetInfoStr);
            
            return ret;
        }
        
        /**
         * GUIを更新する
         * @param data
         * @param header
         * @param packetInfoStr
         */
        private function updateGui(data:ByteArray, header:PcapPktHdr, packetInfoStr:String):void
        {
            // 表示
            var newlineStr:String = "\r\n";
            var text:String = "";
            if (header != null)
            {
                var ts:Timeval = header.ts;
                var date:Date = new Date(ts.tvSec * 1000);
                text += date.toLocaleString();
                text += " capLen:" + header.capLen.toString() + newlineStr;
            }
            text += packetInfoStr + newlineStr;
            text += newlineStr;
            text += PacketUtil.hexDump(data);
            if (_useCaptureThread && _pcapIf.name.indexOf(PcapDefine.PCAP_SRC_FILE_STRING) == 0)
            {
                // CaptureThreadを使用する場合でファイル読み込みの場合、ボタン押下イベントハンドラが終了する前にキャプチャースレッドが稼働するのでGUIが更新されない
                trace(packetInfoStr);
                _textAreaDumpTextList.push(text);
                if (_guiUpdateTimer == null)
                {
                    _guiUpdateTimer = new Timer(10, 0);
                    _guiUpdateTimer.addEventListener(TimerEvent.TIMER, guiUpdateTimerProc);
                    _guiUpdateTimer.start();
                }                
            }
            else
            {
                textAreaDump.text = text;
            }

            if (_pcapDumper != null)
            {
                var pos:int = _pcapDumper.pcapDumpFTell();
                labelDumpFTell.text = pos.toString();
            }
        }

        /**
         * GUI更新タイマーイベントハンドラ
         * @param e
         */
        private function guiUpdateTimerProc(e:TimerEvent):void 
        {
            var text:String = "";
            text = _textAreaDumpTextList.shift();
            textAreaDump.text = text;
            if (_textAreaDumpTextList.length == 0)
            {
                _guiUpdateTimer.stop();
                _guiUpdateTimer.removeEventListener(TimerEvent.TIMER, guiUpdateTimerProc);
                _guiUpdateTimer = null;
                btnStart.label = "Start";
                radioGroupMethodArrival.enabled = true;
                trace("guiUpdateTimerProc done");
            }
        }
        
        /**
         * パケットのパース処理
         * @param data
         * @return GUI表示用文字列
         */
        private function parsePacket(data:ByteArray):String 
        {
            var retStr:String = "";
            //var newlineStr:String = "\r\n";

            // パケットデータをパースする
            var dlt:int = _pcapHandle.pcapDataLink();
            var packet:Packet = Packet.parsePacket(dlt, data);
            if (packet == null)
            {
                return retStr;
            }
            // 一番内側のパケットを取得する
            var lastPacket:Packet = packet.getLastPacket();
            // TcpPacketを指定して取得する
            //var lastPacket:Packet = packet.extractPacket(TcpPacket);
            
            // パケット情報を取得する
            retStr += getQualifiedClassName(lastPacket) + " ";
            if (lastPacket is TcpPacket || lastPacket is UdpPacket)
            {
                // TcpPacketかUdpPacketの場合
                
                var srcAddrAsString:String = "";
                var dstAddrAsString:String = "";
                var srcPort:uint = 0;
                var dstPort:uint = 0;
                var ipPacket:IpPacket = lastPacket.parentPacket as IpPacket;
                if (ipPacket != null)
                {
                    if (ipPacket is Ipv4Packet)
                    {
                        var ipv4Packet:Ipv4Packet = ipPacket as Ipv4Packet;
                        srcAddrAsString = _extension.IpAddrByteArrayToString(SockAddr.AF_INET, ipv4Packet.srcAddress);
                        dstAddrAsString = _extension.IpAddrByteArrayToString(SockAddr.AF_INET, ipv4Packet.dstAddress);
                    }
                    else if (ipPacket is Ipv6Packet)
                    {
                        var ipv6Packet:Ipv6Packet = ipPacket as Ipv6Packet;
                        srcAddrAsString = "[" + _extension.IpAddrByteArrayToString(SockAddr.AF_INET6, ipv6Packet.srcAddress) + "]";
                        dstAddrAsString = "[" + _extension.IpAddrByteArrayToString(SockAddr.AF_INET6, ipv6Packet.dstAddress) + "]";
                    }
                    else
                    {
                        // invalid
                    }
                }
                
                if (lastPacket is TcpPacket)
                {
                    var tcpPacket:TcpPacket = lastPacket as TcpPacket;
                    srcPort = tcpPacket.srcPort;
                    dstPort = tcpPacket.dstPort;
                }
                else if (lastPacket is UdpPacket)
                {
                    var udpPacket:UdpPacket = lastPacket as UdpPacket;
                    srcPort = udpPacket.srcPort;
                    dstPort = udpPacket.dstPort;
                }
                retStr += 
                    srcAddrAsString
                    + ":"
                    + srcPort.toString()
                    + "->"
                    + dstAddrAsString
                    + ":"
                    + dstPort.toString()
                    + " payload length = " + lastPacket.payloadByteAry.length.toString();
            }
            else
            {
                // その他
            }
            return retStr;
        }
    }

}