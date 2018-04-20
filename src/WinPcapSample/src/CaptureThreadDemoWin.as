package
{
    import flash.events.Event;
    import flash.utils.ByteArray;
    import livefan.packet.PacketUtil;
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
    public class CaptureThreadDemoWin extends CaptureThreadDemoWinView
    {
        private var _extension:WinPcapExtension = null;
        private var _pcapHandle:PcapHandle = null;
        private var _pcapIf:PcapIf = null;
		private var _networkName:String = "";
        
        public function CaptureThreadDemoWin(networkName:String)
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
            
			var packetCnt:int = _pcapHandle.getArrivalPacketCount();
			//trace("packet = " + packetCnt);
			for (var i:int = 0; i < packetCnt; i++)
			{
                // 到達パケットを取得する
                var resGetArrival:ResultGetArrival = _pcapHandle.getArrivalPacket();
                var ret:int = resGetArrival.retVal;
                var header:PcapPktHdr = resGetArrival.header as PcapPktHdr;
                var data:ByteArray = resGetArrival.data as ByteArray;
                resGetArrival.dispose(); // 結果を破棄する (取得したheaderはnativeで使用不可となる)
                if (ret != 1)
                {
                    continue;
                }
                //trace(PacketUtil.hexDump(data));

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
                text += PacketUtil.hexDump(data);
                textAreaDump.text = text;
			}
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
    }

}