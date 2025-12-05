{
  "id": "aodv_host",
  "type": "网络节点",
  "subtype": "",
  "desc": "网络设备节点模型",
  "icon": "aodv/radio.png",
  "target": [
    "MIAOSUAN"
  ],
  "macList": [],
  "metadata": {
    "MIAOSUAN": {
      "modules": [
        {
          "name": "AODV",
          "model": "aodv",
          "type": "processor",
          "attributeValues": {
            "Subnet": "0.0.0.0/0"
          },
          "_editorMetadata": {
            "position": {
              "x": 570,
              "y": 82
            },
            "size": {
              "width": 64,
              "height": 64
            },
            "nodeId": "76e6d84a-d843-4aa3-8668-c4727e11a14c"
          }
        },
        {
          "name": "UDP",
          "model": "udp",
          "type": "processor",
          "attributeValues": {},
          "_editorMetadata": {
            "position": {
              "x": 406.0825422879907,
              "y": 159.0650383033377
            },
            "size": {
              "width": 64,
              "height": 64
            },
            "nodeId": "0066ba31-b539-4ab9-bcd8-eb34cd8b89d4"
          }
        },
        {
          "name": "EchoApp",
          "model": "echo_app",
          "type": "processor",
          "attributeValues": {},
          "_editorMetadata": {
            "position": {
              "x": 406.0825422879907,
              "y": 18
            },
            "size": {
              "width": 64,
              "height": 64
            },
            "nodeId": "2129ad64-0ffe-4b1d-a3ed-7cbd8f9611c4"
          }
        },
        {
          "name": "IP",
          "model": "ipv4",
          "type": "processor",
          "attributeValues": {
            "routing enabled": true
          },
          "_editorMetadata": {
            "position": {
              "x": 406.0825422879907,
              "y": 279.5337008989336
            },
            "size": {
              "width": 64,
              "height": 64
            },
            "nodeId": "c0d7c2a8-63d0-496f-a2c1-da56cb1528d0"
          }
        },
        {
          "name": "ARP",
          "model": "arp",
          "type": "processor",
          "attributeValues": {
            "Simulation Efficiency": "Disabled"
          },
          "_editorMetadata": {
            "position": {
              "x": 406.0825422879907,
              "y": 391.03815005692303
            },
            "size": {
              "width": 64,
              "height": 64
            },
            "nodeId": "2b837b39-0a75-4e4a-969b-b9c3eb9de192"
          }
        },
        {
          "name": "MAC",
          "model": "generic_wireless",
          "type": "processor",
          "attributeValues": {
            "电台工作参数": {
              "工作状态": true
            }
          },
          "_editorMetadata": {
            "position": {
              "x": 406.0825422879907,
              "y": 502.3558096901281
            },
            "size": {
              "width": 64,
              "height": 64
            },
            "nodeId": "b0af70bb-d50d-4f14-b456-73892e81aaa3"
          }
        },
        {
          "name": "tx",
          "model": "",
          "type": "radio transmitter",
          "attributeValues": {
            "channel": [
              {
                "data rate": 0,
                "bandwidth": 10,
                "min frequency": 30,
                "spreading code": 0,
                "power": 100,
                "bit capacity": -1,
                "pk capacity": 1000
              }
            ],
            "closure model": "generic_wireless_closure",
            "rxgroup model": "generic_wireless_rxgroup",
            "txdel model": "generic_wireless_txdel"
          },
          "_editorMetadata": {
            "position": {
              "x": 531.1939733187303,
              "y": 566.3558096901281
            },
            "size": {
              "width": 64,
              "height": 64
            },
            "nodeId": "ab32576e-57b2-4611-94f8-ea0210660e4f"
          }
        },
        {
          "name": "rx",
          "model": "",
          "type": "radio receiver",
          "attributeValues": {
            "channel": [
              {
                "data rate": 0,
                "packet formats": "all formatted,unformatted",
                "bandwidth": 10,
                "min frequency": 30,
                "spreading code": 0,
                "processing gain": 0
              }
            ],
            "ecc model": "generic_wireless_ecc"
          },
          "_editorMetadata": {
            "position": {
              "x": 276.0644835412704,
              "y": 566.3558096901281
            },
            "size": {
              "width": 64,
              "height": 64
            },
            "nodeId": "3978d1a1-56ea-4b81-bd61-80860d39c0f2"
          }
        }
      ],
      "streams": [
        {
          "src": "UDP",
          "srcIdx": 0,
          "dst": "AODV",
          "dstIdx": 0,
          "id": "03ed7e67-543b-46fe-8237-6b3600c01e13"
        },
        {
          "src": "AODV",
          "srcIdx": 0,
          "dst": "UDP",
          "dstIdx": 0,
          "id": "d1fdda37-6af2-4e9c-8739-c42aa279406a"
        },
        {
          "src": "UDP",
          "srcIdx": 1,
          "dst": "EchoApp",
          "dstIdx": 0,
          "id": "2c216631-f02f-4e49-aeb6-cbfcbb7423c4"
        },
        {
          "src": "EchoApp",
          "srcIdx": 0,
          "dst": "UDP",
          "dstIdx": 1,
          "id": "fe2e9351-9db5-4194-8c39-31acf81f0987"
        },
        {
          "src": "UDP",
          "srcIdx": 2,
          "dst": "IP",
          "dstIdx": 0,
          "id": "64ea9f02-d20b-4e99-b64b-3db2a77e4fa0"
        },
        {
          "src": "IP",
          "srcIdx": 0,
          "dst": "UDP",
          "dstIdx": 2,
          "id": "c4203a22-acd7-4418-a4fe-2cd201c1c81e"
        },
        {
          "src": "MAC",
          "srcIdx": 0,
          "dst": "tx",
          "dstIdx": 0,
          "id": "6e721190-04d0-4ce5-baf8-39d99400625b"
        },
        {
          "src": "rx",
          "srcIdx": 0,
          "dst": "MAC",
          "dstIdx": 0,
          "id": "ffbdf399-2869-4f33-9fa8-b97d76d5f3f0"
        },
        {
          "src": "MAC",
          "srcIdx": 1,
          "dst": "ARP",
          "dstIdx": 0,
          "id": "64fe6d34-3e98-45f5-ac41-deb3fed60cca"
        },
        {
          "src": "ARP",
          "srcIdx": 0,
          "dst": "MAC",
          "dstIdx": 1,
          "id": "5cf86cdd-a291-4939-bcae-ca3c9b28305a"
        },
        {
          "src": "ARP",
          "srcIdx": 1,
          "dst": "IP",
          "dstIdx": 1,
          "id": "e4b5619c-0c3b-48b3-a6e9-3d317ead8adc"
        },
        {
          "src": "IP",
          "srcIdx": 1,
          "dst": "ARP",
          "dstIdx": 1,
          "id": "f64391b1-82b8-4f23-803d-5e31db0c719f"
        }
      ],
      "notifications": [],
      "pipelinePackages": [
        "generic_wireless"
      ],
      "edgeMeta": [
        {
          "id": "03ed7e67-543b-46fe-8237-6b3600c01e13",
          "type": "packet_stream",
          "src": "UDP",
          "dst": "AODV",
          "vertices": [],
          "connector": {
            "name": "parallel"
          }
        },
        {
          "id": "d1fdda37-6af2-4e9c-8739-c42aa279406a",
          "type": "packet_stream",
          "src": "AODV",
          "dst": "UDP",
          "vertices": [],
          "connector": {
            "name": "parallel"
          }
        },
        {
          "id": "2c216631-f02f-4e49-aeb6-cbfcbb7423c4",
          "type": "packet_stream",
          "src": "UDP",
          "dst": "EchoApp",
          "vertices": [],
          "connector": {
            "name": "parallel"
          }
        },
        {
          "id": "fe2e9351-9db5-4194-8c39-31acf81f0987",
          "type": "packet_stream",
          "src": "EchoApp",
          "dst": "UDP",
          "vertices": [],
          "connector": {
            "name": "parallel"
          }
        },
        {
          "id": "64ea9f02-d20b-4e99-b64b-3db2a77e4fa0",
          "type": "packet_stream",
          "src": "UDP",
          "dst": "IP",
          "vertices": [],
          "connector": {
            "name": "parallel"
          }
        },
        {
          "id": "c4203a22-acd7-4418-a4fe-2cd201c1c81e",
          "type": "packet_stream",
          "src": "IP",
          "dst": "UDP",
          "vertices": [],
          "connector": {
            "name": "parallel"
          }
        },
        {
          "id": "6e721190-04d0-4ce5-baf8-39d99400625b",
          "type": "packet_stream",
          "src": "MAC",
          "dst": "tx",
          "vertices": [],
          "connector": {
            "name": "parallel"
          }
        },
        {
          "id": "ffbdf399-2869-4f33-9fa8-b97d76d5f3f0",
          "type": "packet_stream",
          "src": "rx",
          "dst": "MAC",
          "vertices": [],
          "connector": {
            "name": "parallel"
          }
        },
        {
          "id": "64fe6d34-3e98-45f5-ac41-deb3fed60cca",
          "type": "packet_stream",
          "src": "MAC",
          "dst": "ARP",
          "vertices": [],
          "connector": {
            "name": "parallel"
          }
        },
        {
          "id": "5cf86cdd-a291-4939-bcae-ca3c9b28305a",
          "type": "packet_stream",
          "src": "ARP",
          "dst": "MAC",
          "vertices": [],
          "connector": {
            "name": "parallel"
          }
        },
        {
          "id": "e4b5619c-0c3b-48b3-a6e9-3d317ead8adc",
          "type": "packet_stream",
          "src": "ARP",
          "dst": "IP",
          "vertices": [],
          "connector": {
            "name": "parallel"
          }
        },
        {
          "id": "f64391b1-82b8-4f23-803d-5e31db0c719f",
          "type": "packet_stream",
          "src": "IP",
          "dst": "ARP",
          "vertices": [],
          "connector": {
            "name": "parallel"
          }
        }
      ]
    }
  },
  "attributes": [
    {
      "name": "APP-角色",
      "label": "APP-角色",
      "type": "string",
      "desc": "",
      "unit": "",
      "validator": "",
      "defaultValue": "server",
      "symbolMap": [
        {
          "key": "服务端",
          "value": "server"
        },
        {
          "key": "客户端",
          "value": "client"
        }
      ],
      "allowOtherValues": true,
      "_redirect": {
        "targetModule": "EchoApp",
        "targetAttribute": "role",
        "originalName": "role",
        "description": ""
      }
    },
    {
      "name": "APP-目的地址",
      "label": "APP-目的地址",
      "type": "string",
      "desc": "",
      "unit": "",
      "validator": "",
      "defaultValue": "192.168.2.10",
      "symbolMap": [],
      "allowOtherValues": true,
      "_redirect": {
        "targetModule": "EchoApp",
        "targetAttribute": "dest",
        "originalName": "dest",
        "description": ""
      }
    },
    {
      "name": "IP接口表",
      "label": "IP接口表",
      "type": "array",
      "desc": "物理网络接口配置列表",
      "unit": "",
      "validator": "",
      "defaultValue": [],
      "symbolMap": [],
      "allowOtherValues": true,
      "children": [
        {
          "name": "name",
          "label": "接口名称",
          "type": "string",
          "desc": "网络接口名称",
          "defaultValue": "IF0"
        },
        {
          "name": "ip address",
          "label": "IP地址",
          "type": "string",
          "desc": "接口IP地址",
          "defaultValue": "192.168.1.1"
        },
        {
          "name": "mask",
          "label": "子网掩码",
          "type": "string",
          "desc": "子网掩码，格式如255.255.255.0",
          "defaultValue": "255.255.255.0"
        },
        {
          "name": "mtu",
          "label": "MTU",
          "type": "int",
          "desc": "最大传输单元，单位：字节",
          "defaultValue": 1500
        },
        {
          "name": "speed",
          "label": "接口速率",
          "type": "float",
          "desc": "接口数据传输速率，单位：kbps",
          "defaultValue": 1000000
        },
        {
          "name": "routing protocols",
          "label": "路由协议",
          "type": "string",
          "desc": "支持的路由协议，多个协议用逗号分隔",
          "defaultValue": ""
        }
      ],
      "_redirect": {
        "targetModule": "IP",
        "targetAttribute": "interfaces",
        "originalName": "interfaces",
        "description": "物理网络接口配置列表"
      }
    },
    {
      "name": "MAC工作参数",
      "label": "MAC工作参数",
      "type": "object",
      "desc": "",
      "unit": "",
      "defaultValue": "",
      "symbolMap": [],
      "allowOtherValues": true,
      "children": [
        {
          "name": "工作状态",
          "label": "工作状态",
          "type": "bool",
          "desc": "",
          "unit": "",
          "defaultValue": false,
          "symbolMap": [
            {
              "key": "关闭",
              "value": "false"
            },
            {
              "key": "工作",
              "value": "true"
            }
          ],
          "allowOtherValues": true,
          "children": []
        },
        {
          "name": "数据速率",
          "label": "数据速率",
          "type": "float",
          "desc": "",
          "unit": "kbps",
          "defaultValue": 38.4,
          "symbolMap": [],
          "allowOtherValues": true,
          "children": []
        },
        {
          "name": "工作频段",
          "label": "工作频段",
          "type": "float",
          "desc": "",
          "unit": "MHz",
          "defaultValue": 30,
          "symbolMap": [],
          "allowOtherValues": true,
          "children": []
        },
        {
          "name": "工作频宽",
          "label": "工作频宽",
          "type": "float",
          "desc": "",
          "unit": "kHz",
          "defaultValue": 100,
          "symbolMap": [],
          "allowOtherValues": true,
          "children": []
        },
        {
          "name": "调制解调方案",
          "label": "调制解调方案",
          "type": "string",
          "desc": "",
          "unit": "",
          "defaultValue": "BPSK",
          "symbolMap": [
            {
              "key": "BPSK",
              "value": "BPSK"
            },
            {
              "key": "QPSK",
              "value": "QPSK"
            },
            {
              "key": "16QAM",
              "value": "16QAM"
            },
            {
              "key": "64QAM",
              "value": "64QAM"
            }
          ],
          "allowOtherValues": true,
          "children": []
        },
        {
          "name": "最大传输距离",
          "label": "最大传输距离",
          "type": "float",
          "desc": "",
          "unit": "公里",
          "defaultValue": 999999999,
          "symbolMap": [
            {
              "key": "无限制",
              "value": "999999999.0"
            }
          ],
          "allowOtherValues": true,
          "children": []
        },
        {
          "name": "传输功率",
          "label": "传输功率",
          "type": "float",
          "desc": "",
          "unit": "瓦特",
          "defaultValue": 30,
          "symbolMap": [],
          "allowOtherValues": true,
          "children": []
        },
        {
          "name": "接收灵敏度",
          "label": "接收灵敏度",
          "type": "float",
          "desc": "",
          "unit": "dBm",
          "defaultValue": -100,
          "symbolMap": [],
          "allowOtherValues": true,
          "children": []
        },
        {
          "name": "缓存大小",
          "label": "缓存大小",
          "type": "int",
          "desc": "",
          "unit": "包",
          "defaultValue": 1000,
          "symbolMap": [],
          "allowOtherValues": true,
          "children": []
        },
        {
          "name": "分片生存时间",
          "label": "分片生存时间",
          "type": "float",
          "desc": "",
          "unit": "秒",
          "defaultValue": 20,
          "symbolMap": [],
          "allowOtherValues": true,
          "children": []
        },
        {
          "name": "失效/恢复状态",
          "label": "失效/恢复状态",
          "type": "array",
          "desc": "",
          "unit": "",
          "defaultValue": "",
          "symbolMap": [],
          "allowOtherValues": true,
          "children": [
            {
              "name": "时间",
              "label": "时间",
              "type": "float",
              "desc": "",
              "unit": "",
              "defaultValue": 0,
              "symbolMap": [],
              "allowOtherValues": true,
              "children": []
            },
            {
              "name": "状态",
              "label": "状态",
              "type": "int",
              "desc": "",
              "unit": "",
              "defaultValue": 0,
              "symbolMap": [
                {
                  "key": "0",
                  "value": "失效"
                },
                {
                  "key": "1",
                  "value": "恢复"
                }
              ],
              "allowOtherValues": true,
              "children": []
            }
          ]
        }
      ],
      "_redirect": {
        "targetModule": "MAC",
        "targetAttribute": "电台工作参数",
        "originalName": "电台工作参数",
        "description": ""
      }
    }
  ],
  "ports": []
}
