package
{
    import flash.events.Event;
    import flash.utils.ByteArray;
    import livefan.winpcap.PcapDefine;
    import livefan.winpcap.PcapHandle;
    import livefan.winpcap.PcapIf;
    import livefan.winpcap.PcapPktHdr;
    import livefan.winpcap.ResultAllDevs;
    import livefan.winpcap.ResultGetArrival;
    import livefan.winpcap.ResultPcap;
    import livefan.winpcap.Timeval;
    import livefan.winpcap.WinPcapExtension;
    import livefan.winpcap.WinPcapExtensionEvent;
    import mx.controls.Alert;
    import mx.events.AIREvent;
    
    /**
     * 
     * @author Owner
     */
    public class GatherStatistcsWin extends GatherStatistcsWinView
    {
        private var _extension:WinPcapExtension = null;
        private var _pcapHandle:PcapHandle = null;
        private var _pcapIf:PcapIf = null;
        private var _oldTs:Timeval = null;
        private var _staticsInfoStrList:Vector.<String> = new Vector.<String>();
		private var _networkName:String = "";

        public function GatherStatistcsWin(networkName:String)
        {
            super();
            addEventListener(AIREvent.WINDOW_COMPLETE, initWin);
            addEventListener(Event.CLOSING, closing);
			_networkName = networkName;
        }
    
        private function initWin(e:AIREvent):void 
        {
            // WinPcap拡張インスタンスの生成
            _extension = new WinPcapExtension();
            _extension.addEventListener(WinPcapExtensionEvent.CAPTURETHREAD_PACKETARRIVAL, onCaptureThreadPacketArrival);
            _extension.addEventListener(WinPcapExtensionEvent.CAPTURETHREAD_THREADFUNCFINISHED, onCaptureThreadFinished);
            
            textAreaDump.editable = false;

            _pcapIf = getNetworkAdapter();
            startCapture(_pcapIf.name);
        }
        
        private function closing(e:Event):void 
        {
            stopCapture();
            _extension.dispose();
        }

        private function onCaptureThreadPacketArrival(e:WinPcapExtensionEvent):void 
        {
            if (_pcapHandle == null)
            {
                return;
            }
            
            // 到達パケットを取得する
            var resGetArrival:ResultGetArrival = _pcapHandle.getArrivalPacket();
            var ret:int = resGetArrival.retVal;
            var header:PcapPktHdr = resGetArrival.header as PcapPktHdr;
            var data:ByteArray = resGetArrival.data as ByteArray;
            resGetArrival.dispose(); // 結果を破棄する (取得したheaderはnativeで使用不可となる)
            if (ret != 1)
            {
                return;
            }
            //trace(PacketUtil.hexDump(data));
            var statisticsInfoStr:String = parseStatisticsPacket(header, data);
            if (statisticsInfoStr.length == 0)
            {
                return;
            }

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
            text += statisticsInfoStr + newlineStr;
            //text += PacketUtil.hexDump(data);
            
            text = text.replace(/\r\n/g, "  ");
            text += newlineStr;
            // 10K越え毎に表示をクリア
            if (textAreaDump.text.length > 1000 * 10)
            {
                textAreaDump.text = "";
            }
            textAreaDump.appendText(text);
        }
        
        private function onCaptureThreadFinished(e:WinPcapExtensionEvent):void
        {
            if (_pcapHandle != null)
            {
                // キャプチャー終了済みでない場合、stopCaptureを呼び出す
                Alert.show("CaptureThread was finished by itself. (maybe EOF was detected)", "", Alert.OK, this);
                stopCapture();
            }
            else
            {
                // stopCaptureを呼び出した場合は、このイベント到達時には終了処理済み
            }
        }
        
        private function getNetworkAdapter():PcapIf
        {
            var pcapIf:PcapIf = null;
            // ネットワークインターフェースの一覧を取得
            var source:String = PcapDefine.PCAP_SRC_IF_STRING;
            var resAllDevs:ResultAllDevs = _extension.pcapFindAllDevsEx(source, null);
            if (resAllDevs.retVal != 0)
            {
                Alert.show(resAllDevs.errBuf, "", Alert.OK, this);
                return null;
            }
            var pcapIfs:PcapIf = resAllDevs.pcapIfs;
			pcapIf = null;
            for (var tmpPcapIf:PcapIf = pcapIfs; tmpPcapIf != null; tmpPcapIf = tmpPcapIf.next)
            {
                var name:String = tmpPcapIf.name;
				if (name == _networkName)
				{
					pcapIf = tmpPcapIf;
					break;
				}
			}
            resAllDevs.dispose();
            
            return pcapIf;
        }

        private function startCapture(adapterName:String):Boolean
        {
            var resPcap:ResultPcap = _extension.pcapOpen(adapterName, 65535, PcapDefine.PCAP_OPENFLAG_PROMISCUOUS, 20, null);
            if (resPcap.retVal != 0)
            {
                Alert.show(resPcap.errBuf, "", Alert.OK, this);
                return false;
            }
            this._pcapHandle = resPcap.pcapHandle;

            textAreaDump.text = "";
            this._oldTs = null;
            var retSetMode:int = this._pcapHandle.pcapSetMode(PcapDefine.MODE_STAT);
            
            this._pcapHandle.startCaptureThread(); // CaptureThreadを起動する
            return true;
        }
        
        private function stopCapture():void
        {
            if (_pcapHandle == null)
            {
                return;
            }
            _pcapHandle.stopCaptureThread(); // CaptureThreadを終了する
            _pcapHandle.pcapClose();
            _pcapHandle.dispose();
            _pcapHandle = null;
        }

        private function parseStatisticsPacket(header:PcapPktHdr, data:ByteArray):String 
        {
            var statisticsInfoStr:String = "";
            var newlineStr:String = "\r\n";
            var delay:uint = 0;
            var bps:Number = 0;
            var pps:Number = 0;
            var oldTvSec:uint = 0;
            var oldTvUsec:uint = 0;
            var acceptedPacketCnt:Number = 0;
            var acceptedBytesLen:Number = 0;

            if (this._oldTs != null)
            {
                oldTvSec = this._oldTs.tvSec;
                oldTvUsec = this._oldTs.tvUsec;
            }
            
            delay = (header.ts.tvSec - oldTvSec) * 1000000 + (header.ts.tvUsec - oldTvUsec);
            acceptedPacketCnt = data[0] + (data[1] << 8) + (data[2] << 16) + (data[3] << 24)
                                + (data[4] << 32) + (data[5] << 40) + (data[6] << 48) + (data[7] << 56);
            acceptedBytesLen = data[8] + (data[9] << 8) + (data[10] << 16) + (data[11] << 24)
                                + (data[12] << 32) + (data[13] << 40) + (data[14] << 48) + (data[15] << 56);
            pps = acceptedPacketCnt * 1000000 / delay;
            bps = acceptedBytesLen * 8 * 1000000 / delay;
            if (uint(pps) != 0 || uint(bps) != 0)
            {
                statisticsInfoStr += "acceptedPacketCnt:" + acceptedPacketCnt.toString() + newlineStr;
                statisticsInfoStr += "acceptedBytesLen:" + acceptedBytesLen.toString() + newlineStr;
                statisticsInfoStr += "pps:" + uint(pps).toString() + newlineStr;
                statisticsInfoStr += "bps:" + uint(bps).toString() + newlineStr;
                //trace(statisticsInfoStr);
            }
            else
            {
                statisticsInfoStr = "";
            }
            this._oldTs = header.ts;
            return statisticsInfoStr;
        }
    }

}