/*
 * Copyright (c) 2008 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#define SECURITY_WIN32
#define IO_BUFFER_SIZE  0x10000

#include <windows.h>
#include <security.h>
#include <schnlsp.h>
#include <string>
#include <stdio.h>
#include <stdarg.h>

#include "Log.h"
#include "snetpp.h"

Snet::Snet() {
	this->s = INVALID_SOCKET;
	this->useTls = FALSE;
	this->readbuflen = READBUFSIZE;
	this->readBuffer = NULL;
	this->readBufferSize = 0;
	this->writeBuffer = NULL;
	this->writeBufferLength = 0;
}

Snet::~Snet() {
	if ( writeBuffer != NULL ) {
		LocalFree( writeBuffer );
	}
	if ( readBuffer != NULL ) {
		LocalFree( readBuffer );
	}
	if ( s != INVALID_SOCKET ) {
		closesocket( s );
	}
}
void
Snet::attach( SOCKET s ) {
	this->s = s;
}

int
Snet::close() {
	if ( closesocket( s ) == SOCKET_ERROR ) {
		CosignLog( L"Error closing socket %d", WSAGetLastError() );
	}
	return( 0 );
}

int
Snet::getLine() {

	SNETSOCKETSTATE	state = MOREDATA;
	int	size = 0;
	DWORD	err;
	data.clear();

	if ( useTls ) {
		return( secureRead() );
	}
	while( state != DONE) {
		size = recv( s, readbuf, readbuflen - 1, 0 );
		if ( size == SOCKET_ERROR ) {
			/// throw( SslTestError( (DWORD)WSAGetLastError(), __LINE__, __FUNCTION__ ) );
			err = (DWORD)WSAGetLastError();
			return( -1 );
		}
		if ( size <= 0 ) {
			break;
		}
		readbuf[ size ] = '\0';
		data.append( readbuf );
		if ( readbuf[ size - 1 ] == '\n' ) {
			if ( state == FUZZY ) {
				state = DONE;
			} else if ( size > 1 && readbuf[ size - 2 ] =='\r' ) {
				state = DONE;
			}
		} else if ( readbuf[ size - 1 ] == '\r' ) {
			state = FUZZY;
		}
	}

	return( 0 );
}

int
Snet::secureGetLine() {
	return( -1 );
}

int
Snet::write( std::string str ) {
	if ( useTls ) {
		/// xxx it seems like more error checking should be done here
		secureWrite( str );
	} else {
		/// xxx it seems like more error checking should be done here, too
		send( s, str.c_str(), (int)str.length(), 0 );
	}
	return( 0 );
}

int
Snet::secureWrite( std::string str ) {
	DWORD			msgSize;
	SecBuffer		buffers[4];
	SecBufferDesc   bufferDesc;
	BYTE*			pMsg;
	SECURITY_STATUS	ss;
	int				sendSize;

	pMsg = writeBuffer + streamSizes.cbHeader;
	//_snprintf( (char*)pMsg, writeBufferLength - streamSizes.cbHeader, "%s", str.c_str() );
	_snprintf_s( (char*)pMsg, writeBufferLength - streamSizes.cbHeader, writeBufferLength - streamSizes.cbHeader, "%s", str.c_str() );
 	msgSize = (DWORD)strlen( (char*)pMsg );
//	cout << "Writing:\"" << pMsg << "\"\nsize: " << msgSize << endl;

	buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
	buffers[0].cbBuffer = streamSizes.cbHeader;
	buffers[0].pvBuffer = writeBuffer;

	buffers[1].BufferType = SECBUFFER_DATA;
	buffers[1].cbBuffer = msgSize;
	buffers[1].pvBuffer = pMsg;

	buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
	buffers[2].cbBuffer = streamSizes.cbTrailer;
	buffers[2].pvBuffer = pMsg + msgSize;

	buffers[3].BufferType = SECBUFFER_EMPTY;

	bufferDesc.cBuffers = 4;
	bufferDesc.pBuffers = buffers;
	bufferDesc.ulVersion = SECBUFFER_VERSION;
	
	ss = EncryptMessage( &ctx, 0, &bufferDesc, 0 );

	if ( FAILED(ss) ) {
//		cout << "secureWrite EncryptMessage failed with " << ss << endl;
		return( -1 );
	}

	sendSize = send( s, (char*)writeBuffer, buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer, 0 );

	if ( sendSize == 0 || sendSize == SOCKET_ERROR ) {
//		cout << "secureWrite send failed with " << WSAGetLastError() << endl;
		return( -1 );
	}

//	cout << "Sent " << sendSize << " encrypted bytes." << endl;

	return( 0 );
}

int
Snet::read() {
	if ( useTls ) {
		secureRead();
	} else {
		recv( s, readbuf, readbuflen - 1, 0 );
	}
	return( 0 );
}

int
Snet::secureRead() {

	SecBuffer		buffers[4];
	SecBufferDesc	bufferDesc;
	int				recvSize;
	DWORD			readBufferOffset = 0;
	SECURITY_STATUS	ss;
	SecBuffer*		dataBuffer;
    SecBuffer*		extraBuffer;

	data.clear();
	ss = SEC_E_INCOMPLETE_MESSAGE;
	while( 1 ) {

		if ( ss == SEC_E_INCOMPLETE_MESSAGE || readBufferOffset == 0 ) {
			recvSize = recv( s, (char*)(readBuffer + readBufferOffset), readBufferSize - readBufferOffset, 0 );
	
			if ( recvSize == SOCKET_ERROR ) {
				CosignLog( L"Socket error on recv(): %d", WSAGetLastError() );
				return( -1 );
			}
			if ( recvSize == 0 ) {
				CosignLog( L"Server unexpectedly quit." );
				return( -1 );
			}
			readBufferOffset += recvSize;
		}

		buffers[0].BufferType = SECBUFFER_DATA;
		buffers[0].cbBuffer = readBufferOffset;
		buffers[0].pvBuffer = readBuffer;

		buffers[1].BufferType = SECBUFFER_EMPTY;
		buffers[2].BufferType = SECBUFFER_EMPTY;
		buffers[3].BufferType = SECBUFFER_EMPTY;

		bufferDesc.cBuffers = 4;
		bufferDesc.pBuffers = buffers;
		bufferDesc.ulVersion = SECBUFFER_VERSION;

		ss = DecryptMessage( &ctx, &bufferDesc, 0, NULL );
		/// xxx make a switch?
		if ( ss == SEC_E_INCOMPLETE_MESSAGE ) {
			//CosignTrace0( L"Need to recv() more data.  Continuing..." );
			continue;
		}
		if ( ss == SEC_I_CONTEXT_EXPIRED ) {
			CosignLog( L"Context expired." );
			return( -1 );
		}
		if ( ss != SEC_E_OK &&
			 ss != SEC_I_RENEGOTIATE &&
			 ss != SEC_I_CONTEXT_EXPIRED ) {
			 /// xxx need to throw this ss error so's it can be decoded into human-readble textz0rs
			CosignLog( L"DecryptMessage() failed: 0x%x", ss );
			if ( ss == SEC_E_INVALID_TOKEN ) {
				//CosignTrace0( L"Can SEC_E_INVALID_TOKEN be ignored?" );
				return( 0 );
			}
			if ( ss == SEC_E_DECRYPT_FAILURE ) {
				return( 0 );
			}
			return( -1 );
		}
		/*switch ( ss ) {
			case SEC_E_OK:
				CosignTrace0( L"ss is SEC_E_OK" );
				break;
			case SEC_I_RENEGOTIATE:
				CosignTrace0( L"ss is SEC_I_RENEGOTIATE" );
				break;
			case SEC_I_CONTEXT_EXPIRED:
				CosignTrace0( L"ss is SEC_I_CONTEXT_EXPIRED" );
				break;
			default:
				break;
		}*/
		extraBuffer = NULL;
		dataBuffer = NULL;
		for ( int i = 1; i < 4; i++ ) {
			if ( dataBuffer == NULL && buffers[i].BufferType == SECBUFFER_DATA ) {
				dataBuffer = &buffers[i];
			}
			if ( buffers[i].BufferType == SECBUFFER_EXTRA ) {
			}
			if ( extraBuffer == NULL && buffers[i].BufferType == SECBUFFER_EXTRA ) {
				extraBuffer = &buffers[i];
			}
		}
		if ( dataBuffer != NULL ) {
			data.append( (char*)dataBuffer->pvBuffer, dataBuffer->cbBuffer );
			CosignTrace2( "Decrypted %u bytes as: %s", dataBuffer->cbBuffer, data.c_str() );
			if ( dataBuffer->cbBuffer == 0 ) {
				CosignTrace0( L"cbBuffer is 0" );
			}
		}
		if ( extraBuffer != NULL ) {
			MoveMemory( readBuffer, extraBuffer->pvBuffer, extraBuffer->cbBuffer );
			readBufferOffset = extraBuffer->cbBuffer;
		} else {
			readBufferOffset = 0;
			break;
		}

		if ( ss == SEC_I_RENEGOTIATE ) {
			CosignLog( L"Need to renegotiate TLS connection.  Not yet implemented." );
			return( -1 );
		}
	}
	return( 0 );
}

int
Snet::startTls( PCCERT_CONTEXT	certCtx, WCHAR*	server ) {

	if ( useTls ) {
		return( 2 );
	}

	ULONG			contextAttributes;
	SECURITY_STATUS ss;
	TimeStamp		ts;
	SecBufferDesc	initBuffersDesc;
	SecBuffer		initBuffers[1];
	int		len;
	DWORD	sspiFlags;


	CredHandle		hc;
	TimeStamp		expires;
	SCHANNEL_CRED	screds = {0};

	screds.dwVersion = SCHANNEL_CRED_VERSION;
	screds.cCreds = 1;
	screds.paCred = &certCtx;
		
#ifdef _COSIGN_TRACE
	if ( certCtx == NULL ) {
		CosignLog( L"Cert context is NULL." );
	} else {
		CosignLog( L"Cert context is 0x%x", certCtx );
	}
	CosignLog( L"Acquire credentials handle" );
#endif
	ss = AcquireCredentialsHandle(
			NULL,
			UNISP_NAME,
			SECPKG_CRED_OUTBOUND,
			NULL,
			&screds,
			NULL,
			NULL,
			&hc,
			&expires );
	if ( ss == SEC_E_INSUFFICIENT_MEMORY ) {
		CosignLog( L"Not enought memory" );
	} else if ( ss != S_OK ) {
		CosignLog( L"AcquireCredentialsHandle failed with 0x%x", ss );
		return( -1 );
	}
	CosignTrace0( L"Acquired Credentials handle" );

	contextAttributes = ISC_REQ_SEQUENCE_DETECT   |
						ISC_REQ_REPLAY_DETECT     |
						ISC_REQ_CONFIDENTIALITY   |
						ISC_RET_EXTENDED_ERROR    |
						ISC_REQ_ALLOCATE_MEMORY   |
						ISC_REQ_STREAM;

	initBuffers[0].BufferType = SECBUFFER_TOKEN;
	initBuffers[0].cbBuffer = 0;
	initBuffers[0].pvBuffer = NULL;

	initBuffersDesc.cBuffers = 1;
	initBuffersDesc.pBuffers = initBuffers;
	initBuffersDesc.ulVersion = SECBUFFER_VERSION;
	
	CosignTrace0( L"Initializing security context" );
	ss = InitializeSecurityContext(
			&hc,
			NULL,
			server,
			contextAttributes,
			0, 0, NULL, 0,
			&ctx,
			&initBuffersDesc,
			&sspiFlags,
			&ts );
	
	if ( ss != SEC_I_CONTINUE_NEEDED ) {
		CosignLog( L"InitializeSecurityContext needs to continue" );
		return( -1 );
	}
	
	if ( initBuffers[0].cbBuffer != 0 && initBuffers[0].pvBuffer != NULL ) {
		
		CosignTrace1( L"Sending blob of size %u", initBuffers[0].cbBuffer );
		len = send( s, (char*)initBuffers[0].pvBuffer, initBuffers[0].cbBuffer, 0 );
		
		if ( len == SOCKET_ERROR || len == 0 ) {
			FreeContextBuffer( initBuffers[0].pvBuffer );
			CosignLog( L"Could not send, error = %d", WSAGetLastError() );
			return( -1 );
		}
		CosignTrace1( L"Sent %d bytes of handshake (1)", len );
		FreeContextBuffer( initBuffers[0].pvBuffer );
		initBuffers[0].pvBuffer = NULL;
	}

	// Client handshake loop

	char*	ioBuffer;
	DWORD	ioBufferSize = 0;
	int		recvSize;
	int		sendSize;
	SecBufferDesc	inBuffersDesc;
	SecBuffer		inBuffers[2];
	SecBufferDesc	outBuffersDesc;
	SecBuffer		outBuffers[1];
	SecBuffer		extraBuffer;

	ioBuffer = (char*)LocalAlloc( LMEM_FIXED, IO_BUFFER_SIZE );
	if ( ioBuffer == NULL ) {
		CosignLog( L"Not enough memory for LocalAlloc" );
		return( -1 );
	}

	while ( ss == SEC_I_CONTINUE_NEEDED ||
		    ss == SEC_E_INCOMPLETE_MESSAGE ||
			ss == SEC_I_INCOMPLETE_CREDENTIALS )
	{
		if ( ioBufferSize == 0 || ss == SEC_E_INCOMPLETE_MESSAGE ) {
			recvSize = recv( s, (char*)(ioBuffer + ioBufferSize), IO_BUFFER_SIZE - ioBufferSize, 0 );
			if ( recvSize == SOCKET_ERROR ) {
				CosignLog( L"recv() socket error: %d", WSAGetLastError() );
				return( -1 );
			}
			if ( recvSize == 0 ) {
				CosignTrace0( L"No data recv()'ed!" );
				return( -1 );
			}
			ioBufferSize += recvSize;
			CosignTrace1( L"Received %d bytes", recvSize );
		}
		inBuffers[0].pvBuffer = ioBuffer;
		inBuffers[0].cbBuffer = ioBufferSize;
		inBuffers[0].BufferType = SECBUFFER_TOKEN;

		inBuffers[1].pvBuffer = NULL;
		inBuffers[1].cbBuffer = 0;
		inBuffers[1].BufferType = SECBUFFER_EMPTY;

		inBuffersDesc.cBuffers = 2;
		inBuffersDesc.pBuffers = inBuffers;
		inBuffersDesc.ulVersion = SECBUFFER_VERSION;

		outBuffers[0].pvBuffer = NULL;
		outBuffers[0].cbBuffer = 0;
		outBuffers[0].BufferType = SECBUFFER_TOKEN;

		outBuffersDesc.cBuffers = 1;
		outBuffersDesc.pBuffers = outBuffers;
		outBuffersDesc.ulVersion = SECBUFFER_VERSION;

		ss  = InitializeSecurityContext(
				&hc,
				&ctx,
				NULL,
				contextAttributes,
				0, 
				0,
				&inBuffersDesc,
				0,
				NULL,
				&outBuffersDesc,
				&sspiFlags,
				&ts );
		if ( ss == SEC_E_OK ||
			 ss == SEC_I_CONTINUE_NEEDED ||
			 (FAILED(ss) && (sspiFlags & ISC_RET_EXTENDED_ERROR) ) ){

			if ( outBuffers[0].cbBuffer != 0 && outBuffers[0].pvBuffer != NULL ) {
				CosignTrace0( L"Sending handshake data..." );
				sendSize = send( s, (char*)outBuffers[0].pvBuffer, outBuffers[0].cbBuffer, 0 );
				if ( sendSize == SOCKET_ERROR || sendSize == 0 ) {
					CosignTrace0( L"Could not send() data to server" );
					FreeContextBuffer( outBuffers[0].pvBuffer );
					DeleteSecurityContext( &ctx );
					return( -1 );
				}
				CosignTrace1( L"Sent %d bytes of handshake(2).", sendSize );
				FreeContextBuffer( outBuffers[0].pvBuffer );
				outBuffers[0].pvBuffer = NULL;
			}
		}

		if ( ss == SEC_E_INCOMPLETE_MESSAGE ) {
			CosignTrace0( L"Incomplete message, getting more data..." );
			continue;
		}

		if ( ss == SEC_E_OK ) {
			CosignTrace0( L"Handshaked success!" );

			if ( inBuffers[1].BufferType == SECBUFFER_EXTRA ) {
				CosignTrace0( L"Extra buffer data found" );
				extraBuffer.pvBuffer = LocalAlloc( LMEM_FIXED, inBuffers[1].cbBuffer );
				if ( extraBuffer.pvBuffer == NULL ) {
					CosignLog( L"Not enough memory for extraBuffer" );
					return( -1 );
				}
				MoveMemory( extraBuffer.pvBuffer, ioBuffer + (ioBufferSize - inBuffers[1].cbBuffer), inBuffers[1].cbBuffer );
				extraBuffer.cbBuffer = inBuffers[1].cbBuffer;
				extraBuffer.BufferType = SECBUFFER_TOKEN;
			} else {
				extraBuffer.cbBuffer = 0;
				extraBuffer.pvBuffer = NULL;
				extraBuffer.BufferType = SECBUFFER_EMPTY;
			}
			CosignTrace0( L"Breaking out of loopage" );
			break;
		}

		if( FAILED(ss)) {
			CosignLog( L"InitializeSecurityContext failed with 0x%x", ss );
			return( -1 );
		}

		if ( ss == SEC_I_INCOMPLETE_CREDENTIALS ) {
			CosignLog( L"Server asked for credentials.  Not yet implemented." );
			return( -1 );
		}

		if ( inBuffers[1].BufferType == SECBUFFER_EXTRA ) {
			CosignTrace0( L"Moving extra data" );
			MoveMemory( ioBuffer,
				ioBuffer + ( ioBufferSize - inBuffers[1].cbBuffer ),
				inBuffers[1].cbBuffer );
			ioBufferSize = inBuffers[1].cbBuffer;
		} else {
			ioBufferSize = 0;
		}
		CosignTrace0( L"Looping..." );
	}

	LocalFree( ioBuffer );
	CosignTrace0( L"Handshake complete." );
	useTls = TRUE;
	if ( setStreamBufferSize() != 0 ) {
		return( -1 );
	}
	return( 0 );
}

int
Snet::setStreamBufferSize() {

	SECURITY_STATUS ss;

	ss = QueryContextAttributes( &ctx, SECPKG_ATTR_STREAM_SIZES, &streamSizes );
	if ( ss != SEC_E_OK ) {
//		cout << "QueryContextAttributes failed " << ss << endl;
		return( -1 );
	}

//	cout << "Stream Sizes:"
//		"\nHeader: " << streamSizes.cbHeader <<
//		"\nMaximum Message: " << streamSizes.cbMaximumMessage <<
//		"\nTrailer: " << streamSizes.cbTrailer << endl;

	readBufferSize = writeBufferLength = streamSizes.cbHeader + streamSizes.cbMaximumMessage + streamSizes.cbTrailer;

	writeBuffer = (BYTE*)LocalAlloc(LMEM_FIXED, writeBufferLength );
	readBuffer = (BYTE*)LocalAlloc(LMEM_FIXED, readBufferSize );

	if ( writeBuffer == NULL || readBuffer == NULL ) {
//		cout << "No memory to allocate read and write buffers" << endl;
		return( -1 );
	}
	return( 0 );
}
