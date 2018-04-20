package
{
    import flash.events.Event;
    import flash.events.TimerEvent;
    import flash.utils.ByteArray;
    import flash.utils.Timer;
    import livefan.packet.PacketUtil;
    import livefan.winpcap.PcapDefine;
    import livefan.winpcap.PcapHandle;
    import livefan.winpcap.PcapIf;
    import livefan.winpcap.PcapPktHdr;
    import livefan.winpcap.ResultAllDevs;
    import livefan.winpcap.ResultPcap;
    import livefan.winpcap.ResultPcapNext;
    import livefan.winpcap.Timeval;
    import livefan.winpcap.WinPcapExtension;
    import mx.controls.Alert;
    import mx.events.AIREvent;
    
    /**
     * 
     * @author Owner
     */
    public class PcapNextDemoWin extends PcapNextDemoWinView
    {
        private static const MaxPacketCntToGet:int = 10000;
        
        private var _extension:WinPcapExtension = null;
        private var _pcapIf:PcapIf = null;
        private var _pcapHandle:PcapHandle = null;
        private var _timer:Timer = null;
        private var _timerProcRunning:Boolean = false;
		private var _networkName:String = "";
        
        public function PcapNextDemoWin(networkName:String)
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
            
            textAreaDump.editable = false;

            _pcapIf = getNetworkAdapter();
            startCapture(_pcapIf.name);
        }

        private function closing(e:Event):void 
        {
            stopCapture();
            _extension.dispose();
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
            
            startTimer();
            return true;
        }
        
        private function stopCapture():void
        {
            if (_pcapHandle == null)
            {
                return;
            }
            killTimer();
            _pcapHandle.pcapClose();
            _pcapHandle.dispose();
            _pcapHandle = null;
        }

        private function startTimer():void
        {
            _timer = new Timer(50, 0);
            _timer.addEventListener(TimerEvent.TIMER, timerProc);
            _timer.start();
        }
        
        private function killTimer():void
        {
            if (_timer != null)
            {
                _timer.stop();
                _timer.removeEventListener(TimerEvent.TIMER, timerProc);
                _timer = null;
            }
        }
        
        private function timerProc(e:TimerEvent):void 
        {
            if (_timerProcRunning)
            {
                return;
            }
            _timerProcRunning = true;
            
            var ret:int = 0;
            var maxPacketCnt:int = MaxPacketCntToGet;
            var packetCnt:int = 0;
            
            while (packetCnt < maxPacketCnt)
            {
                ret = getCapturedData();
                if (ret != 1)
                {
                    break;
                }
                packetCnt++;
            }
            
            _timerProcRunning = false;
        }

        private function getCapturedData():int
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
                return ret;
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
            
            return ret;
        }
    }

}