package org.example.proxy;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpServerCodec;
import org.example.config.ProxyConfig;
import org.example.handlers.FileProcessingHandler;
import org.example.services.StorageServiceFactory;
import org.example.services.MetricsServiceImpl;
import org.example.services.VaultService;
import org.example.services.VaultTokenRefresher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ProxyServer {
    private static final Logger logger = LoggerFactory.getLogger(ProxyServer.class);
    private static final ProxyConfig config = ProxyConfig.getInstance();
    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private ChannelFuture serverChannel;
    private StorageServiceFactory storageServiceFactory;
    private MetricsServiceImpl metricsService;

    public ProxyServer(StorageServiceFactory storageServiceFactory) {
        this.metricsService = new MetricsServiceImpl();
        this.storageServiceFactory = storageServiceFactory;
    }

    public void start() throws Exception {
        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();
        
        try {
            ServerBootstrap bootstrap = new ServerBootstrap()
                    .group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ch.pipeline().addLast(
                                    new HttpServerCodec(),
                                    new FileProcessingHandler(storageServiceFactory, metricsService)
                            );
                        }
                    })
                    .option(ChannelOption.SO_BACKLOG, 128)
                    .childOption(ChannelOption.SO_KEEPALIVE, true); 

            int port = config.getProxyPort();
            serverChannel = bootstrap.bind(port).sync();
            logger.info("Proxy Server started on port {}", port);
            
            // Start Vault token refresher
            VaultService vaultService = new VaultService();
            new Thread(new VaultTokenRefresher(vaultService, 300)).start(); // refresh every 5 mins
            
            // Add configuration reload capability
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                logger.info("Reloading configuration...");
                config.reload();
            }));
            
            serverChannel.channel().closeFuture().sync();
        } finally {
            stop();
        }
    }

    public void stop() {
        if (bossGroup != null) {
            bossGroup.shutdownGracefully();
        }
        if (workerGroup != null) {
            workerGroup.shutdownGracefully();
        }
        if (serverChannel != null) {
            serverChannel.channel().close();
        }
        logger.info("Proxy Server stopped");
    }
}
