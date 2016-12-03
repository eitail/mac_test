#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <pthread.h>

#include "keymnglog.h"
#include "keymngserverop.h"
#include "poolsocket.h"
#include "keymng_msg.h"
#include "myipc_shm.h"

#include "keymng_shmop.h"
//#include "icdbapi.h"
//#include "keymng_dbop.h"

//读配置文件获取数据库的连接信�?user pw sid
//从数据库�?获取服务器的配置参数

int MngServer_InitInfo(MngServer_Info *svrInfo)
{
	int 		ret = 0;
	
	KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[1], ret,"func MngServer_InitInfo() Begin");
	
	strcpy(svrInfo->serverId, "0001");
	
	strcpy(svrInfo->dbuse, "SECMNG");
	strcpy(svrInfo->dbpasswd, "SECMNG");
	strcpy(svrInfo->dbsid, "orcl");
	svrInfo->dbpoolnum = 10;
	
	strcpy(svrInfo->serverip, "127.0.0.1");
	svrInfo->serverport = 8001;
	
	svrInfo->maxnode = 10;
	svrInfo->shmkey = 0x01;
	svrInfo->shmhdl = 0;
	

	//初始化共享内�?
	ret = KeyMng_ShmInit(svrInfo->shmkey, svrInfo->maxnode, &svrInfo->shmhdl);
	if (ret != 0)
	{
		printf("func KeyMng_ShmInit() err:%d \n", ret);
		return ret;
	}
	printf("\nkeymngserver 初始化共享内存ok\n");
	
		
	KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[1], ret,"func MngServer_InitInfo() End");
	return 0;

}

static int g_seckeyid = 100;

int MngServer_Agree(MngServer_Info *svrInfo, MsgKey_Req *msgkeyReq, unsigned char **outData, int *datalen)
{
	int		ret = 0, i = 0;
	
	MsgKey_Res			msgKeyRes;
	
	memset(&msgKeyRes, 0, sizeof(MsgKey_Res));
	
	
	KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[1], ret,"func MngServer_Agree() Begin");
	
	//组织应答报文
	msgKeyRes.rv = 0;
	strcpy(msgKeyRes.clientId, msgkeyReq->clientId);
	
	/* 
	if ( strcmp(msgkeyReq->serverId, svrInfo->serverId) == 0)
	{
		msgKeyRes.rv = MngSvr_ParamErr;
	}
	*/
	
	KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[1], ret,"11111111111111111111");
	strcpy(msgKeyRes.serverId, msgkeyReq->serverId);
	
	for (i=0; i<64; i++)
	{
		msgKeyRes.r2[i] = 'a' + i;
	}
	msgKeyRes.seckeyid = ++g_seckeyid;
	KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[1], ret,"2222222222");
	
	//编码应答报文
	ret = MsgEncode(&msgKeyRes, ID_MsgKey_Res, outData, datalen);
	//ret = 200;
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret,"func MsgEncode() err");
		goto End;
	}
	
	//协商密钥 写共享内�?
	
	KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[1], ret,"33333333333333");
	//密钥协商	
	 NodeSHMInfo 		nodeInfo;
	 memset(&nodeInfo, 0, sizeof(NodeSHMInfo));
	 nodeInfo.status = 0;
	 strcpy(nodeInfo.clientId,  msgkeyReq->clientId);
	 strcpy(nodeInfo.serverId, msgkeyReq->serverId);
	 nodeInfo.seckeyid = msgKeyRes.seckeyid ; 
	
	//r1 abc.... r2:123... 
	// a1 b2 c3 .....
	for (i=0; i<64; i++)
	{
		nodeInfo.seckey[2*i] = msgkeyReq->r1[i];
		nodeInfo.seckey[2*i +1] = msgKeyRes.r2[i];
	}
	
	KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[1], ret,"44444444444444444");
	//写网点密�?
	ret = KeyMng_ShmWrite(svrInfo->shmhdl, svrInfo->maxnode, &nodeInfo);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret,"func KeyMng_ShmWrite() err");
		goto End;
	}
	KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[1], ret,"555555555555555555");
End:
	
	KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[1], ret,"func MngServer_Agree() End");
	return ret;	
}




int MngServer_Check(MngServer_Info *svrInfo, MsgKey_Req *msgkeyReq, unsigned char **outData, int *datalen)
{
	int		ret = 0, i = 0;

	MsgKey_Res			msgKeyRes;

	memset(&msgKeyRes, 0, sizeof(MsgKey_Res));
    msgKeyRes.rv = -1;

	KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[1], ret, "func MngServer_Agree() Begin");

	//组织应答报文
	strcpy(msgKeyRes.clientId, msgkeyReq->clientId);
	strcpy(msgKeyRes.serverId, msgkeyReq->serverId);

	for (i = 0; i<64; i++)
	{
		msgKeyRes.r2[i] = 'a' + i;
	}
	msgKeyRes.seckeyid = ++g_seckeyid;
	
	KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[1], ret, "33333333333333");
	//密钥协商	
	NodeSHMInfo 		nodeInfo;
	memset(&nodeInfo, 0, sizeof(NodeSHMInfo));
	strcpy(nodeInfo.clientId, msgKeyRes.clientId);
	strcpy(nodeInfo.serverId, msgKeyRes.serverId);


	KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[1], ret, "KeyMng_ShmRead begin");
	//写网点密�?
	ret = KeyMng_ShmRead(svrInfo->shmhdl, msgKeyRes.clientId, msgKeyRes.serverId,svrInfo->maxnode, &nodeInfo);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret, "func KeyMng_ShmRead() err");
		goto End;
	}
    printf("memcmp befor rv:%d\n",msgKeyRes.rv);
	ret = memcmp(nodeInfo.seckey, msgkeyReq->r1, 8);
    printf("memcmp(nodeInfo.seckey, msgkeyReq->r1, 8) ret = %d", ret);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret, "func memcmp() err"); 
		goto End;
	}

	msgKeyRes.rv = 0;

	//编码应答报文
	ret = MsgEncode(&msgKeyRes, ID_MsgKey_Res, outData, datalen);
	//ret = 200;
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret, "func MsgEncode() err");
		goto End;
	}

	KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[1], ret, "555555555555555555");
End:

	KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[1], ret, "func MngServer_Agree() End");
	return ret;
}
