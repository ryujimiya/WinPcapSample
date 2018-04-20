package
{
    import flash.events.Event;
    import flash.events.MouseEvent;
    import flash.net.NetworkInfo;
    import flash.net.NetworkInterface;
    import flash.utils.ByteArray;
    import livefan.packet.PacketUtil;
    import livefan.winpcap.PcapDefine;
    import livefan.winpcap.PcapHandle;
    import livefan.winpcap.PcapIf;
    import livefan.winpcap.PcapPktHdr;
    import livefan.winpcap.PcapSendQueue;
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
    public class SendPacketDemoWin extends SendPacketDemoWinView
    {
        private var _extension:WinPcapExtension = null;
        private var _pcapHandle:PcapHandle = null;
        private var _pcapIf:PcapIf = null;
		private var _networkName:String = "";
        
        public function SendPacketDemoWin(networkName:String)
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
            checkBoxUseQueue.selected = false;
            btnSend.addEventListener(MouseEvent.CLICK, btnSendClick);
            
            _pcapIf = getNetworkAdapter();
            var macAddrStr:String = getMacMaddressAsString(_pcapIf.name);
            textInputSrcMac.text = macAddrStr;
            textInputDstMac.text = macAddrStr;

            openDevice(_pcapIf.name);
        }
        
        private function closing(e:Event):void 
        {
            closeDevce();
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
        
        private function openDevice(adapterName:String):Boolean
        {
            var resPcap:ResultPcap = _extension.pcapOpen(adapterName, 65535, PcapDefine.PCAP_OPENFLAG_PROMISCUOUS, 20, null);
            if (resPcap.retVal != 0)
            {
                Alert.show(resPcap.errBuf, "", Alert.OK, this);
                return false;
            }
            this._pcapHandle = resPcap.pcapHandle;
            return true;
        }
        
        private function closeDevce():void
        {
            if (_pcapHandle == null)
            {
                return;
            }
            _pcapHandle.pcapClose();
            _pcapHandle.dispose();
            _pcapHandle = null;
        }

        private function btnSendClick(e:MouseEvent):void 
        {
            var srcMacAddressStr:String = textInputSrcMac.text;
            var dstMacAddressStr:String = textInputDstMac.text;
            var srcMacAddressByteAry:ByteArray = macAddressStrToByteArray(srcMacAddressStr);
            var dstMacAddressByteAry:ByteArray = macAddressStrToByteArray(dstMacAddressStr);
            if (srcMacAddressByteAry == null)
            {
                Alert.show("source MacAddress is invalid", "", Alert.OK, this);
                return;
            }
            if (dstMacAddressByteAry == null)
            {
                Alert.show("destination MacAddress is invalid", "", Alert.OK, this);
                return;
            }
            
            const packetCnt:int = 100;
            var buf:ByteArray = new ByteArray();
            buf.length = 100;
            buf.position = 0;
            buf.writeBytes(srcMacAddressByteAry, 0, 6);
            buf.position = 6;
            buf.writeBytes(dstMacAddressByteAry, 0, 6);
            for (var i:int = 12; i < buf.length; i++)
            {
                buf[i] = i;
            }
            
            var ret:int = 0;
            var totalLen:uint = 0;
            var iPacketIndex:int;
            var text:String = "";
            var newlineStr:String = "\r\n";
            
            text = PacketUtil.hexDump(buf);
            text += newlineStr;
            text += "sending " + packetCnt.toString() + " packets..." + newlineStr;

            if (checkBoxUseQueue.selected)
            {
                // Extra 16 bytes are needed. (the size of struct pcap_pkthdr in native C)
                var memSize:int = (buf.length + 16) * packetCnt;
                var queue:PcapSendQueue = _extension.pcapSendQueueAlloc(memSize);
                
                text += "queue.maxLen:" + queue.maxLen.toString() + newlineStr;

                for (iPacketIndex = 0; iPacketIndex < packetCnt; iPacketIndex++)
                {
                    var header:PcapPktHdr = _extension.newPcapPktHdr();
                    header.capLen = buf.length; // WinPcapで参照しているのはこちら
                    header.len = buf.length;
                    var date:Date = new Date();
                    header.ts.tvSec = date.time / 1000;
                    header.ts.tvUsec = date.getMilliseconds() * 1000;
                    ret = queue.pcapSendQueueQueue(header, buf);
                    if (ret == 0)
                    {
                        totalLen += buf.length;
                    }
                    header.dispose();
                    
                    text += "pcapSendQueueQueue ret:" + ret.toString()
                            + "   queue.len:" + queue.len.toString() + newlineStr;
                }

                var sync:int = 0;
                var sendLen:uint = _pcapHandle.pcapSendQueueTransmit(queue, sync);
                if (ret < queue.len)
                {
                    // 送信失敗
                }
                text += "pcapSendQueueTransmit sendLen:" + sendLen.toString() + newlineStr;
                text += "totalLen:" + totalLen.toString() + newlineStr;

                queue.dispose();
            }
            else
            {
                for (iPacketIndex = 0; iPacketIndex < packetCnt; iPacketIndex++)
                {
                    ret = _pcapHandle.pcapSendPacket(buf);
                    if (ret == 0)
                    {
                        totalLen += buf.length;
                    }
                    text += "pcapSendPacket ret:" + ret.toString() + newlineStr;
                }
                text += "totalLen:" + totalLen.toString() + newlineStr;
            }
            
            textAreaDump.text = text;
        }
        
        private static function getMacMaddressAsString(adapterName:String):String
        {
            var hardwareAdressAsString:String = "";
            var networkInfo:NetworkInfo = NetworkInfo.networkInfo;
            var networkIfs:Vector.<NetworkInterface> = networkInfo.findInterfaces();
            if (networkIfs != null && networkIfs.length > 0)
            {
                for each(var networkIf:NetworkInterface in networkIfs)
                {
                    if (!networkIf.active)
                    {
                        continue;
                    }
                    if (adapterName.indexOf(networkIf.name) >= 0)
                    {
                        hardwareAdressAsString = networkIf.hardwareAddress;
                        break;
                    }
                }
            }
            return hardwareAdressAsString;
        }
        
        private static function macAddressStrToByteArray(macAddressStr:String):ByteArray
        {
            var tokens:Array = null;
            var macAddressByteAry:ByteArray = null;

            if (macAddressStr == null || macAddressStr.length == 0)
            {
                return null;
            }
            if (macAddressStr.indexOf(":") >= 0)
            {
                tokens = macAddressStr.split(":");
            }
            else if (macAddressStr.indexOf("-") >= 0)
            {
                tokens = macAddressStr.split("-");
            }
            else
            {
                return null;
            }
            if (tokens.length != 6)
            {
                return null;
            }
            macAddressByteAry = new ByteArray();
            macAddressByteAry.length = 6;
            for (var i:int = 0; i < macAddressByteAry.length; i++)
            {
                var token:String = tokens[i] as String;
                macAddressByteAry[i] = parseInt(token, 16);
            }
            return macAddressByteAry;
        }
    }

}