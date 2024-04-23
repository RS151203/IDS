import threading
import time
import pandas as pd
from sklearn.preprocessing import StandardScaler
from network_data import PacketSniffer

sniffer = PacketSniffer()
log_sniffer = PacketSniffer()


def update_network_live_feed(network_data_queue):
    sniffer.start_sniffing()
    sniffer.start_df_update()
    while True:
        network_data = sniffer.get_df_flows()
        network_data_queue.put(network_data)
        time.sleep(1)
        if sniffer.sniffing == False:
            sniffer.stop_sniffing_and_df_updating()
            break


def update_network_log_data(os_name, log_path, network_log_data_queue):
    log_sniffer.start_sniffing()
    log_sniffer.start_df_update()
    while True:
        network_log_data = log_sniffer.get_per_min_df_flows()
        if not network_log_data.empty:
            network_log_data_queue.put(network_log_data)
            timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
            filename = ""
            if os_name == "nt":
                filename = log_path + f"\log_{timestamp}.csv"
            elif os_name == "posix":
                filename = log_path + f"/log_{timestamp}.csv"
            df = pd.DataFrame(network_log_data)
            df.to_csv(filename, index=False)
            log_sniffer.empty_df_flows()
        for i in range(60):
            time.sleep(1)
            if log_sniffer.sniffing == False:
                log_sniffer.stop_sniffing_and_df_updating()
                break


def update_alert_queue(model, network_log_data_queue, alert_queue):
    while True:
        if not network_log_data_queue.empty():
            test_data = network_log_data_queue.get()
            # Evaluate the model
            X_test = test_data.iloc[:, :].values
            scaler = StandardScaler()
            X_test = scaler.fit_transform(X_test)

            # Make predictions
            y_pred = model.predict(X_test)
            y_pred_binary = (y_pred > 0.5).astype(int)

            # Calculate the percentage of 0s in predictions
            zero_percentage = (y_pred_binary == 0).mean()

            # Print result based on the percentage of 0s
            if zero_percentage >= 0.75 and zero_percentage <= 1:
                alert_queue.put("CLEAN")
            elif zero_percentage >= 0.60 and zero_percentage <= 0.75:
                alert_queue.put("LOW")
            elif zero_percentage >= 0.45 and zero_percentage <= 0.60:
                alert_queue.put("MEDIUM")
            else:
                alert_queue.put("HIGH")
        for i in range(60):
            time.sleep(1)
            if log_sniffer.sniffing == False:
                log_sniffer.stop_sniffing_and_df_updating()
                break


live_feed_thread = []


def start_live_feed(network_data_queue):
    if len(live_feed_thread) == 1:
        for thread in live_feed_thread:
            if thread.is_alive() == True:
                thread.join()
                live_feed_thread.clear()
                start_live_feed(network_data_queue)
    elif len(live_feed_thread) == 0:
        live_feed_thread.append(threading.Thread(target=update_network_live_feed, args=(network_data_queue,)))
        for thread in live_feed_thread:
            thread.start()
    else:
        pass


def stop_live_feed():
    sniffer.sniffing = False
    sniffer.df_updating = False


log_and_alert_thread = []


def start_log_and_alert(os_name, log_path, model, network_log_data_queue, alert_queue):
    if len(log_and_alert_thread) == 2:
        for thread in log_and_alert_thread:
            if thread.is_alive() == True:
                thread.join()
                log_and_alert_thread.clear()
                start_log_and_alert(os_name, log_path, model, network_log_data_queue, alert_queue)
    elif len(log_and_alert_thread) == 0:
        log_and_alert_thread.append(threading.Thread(target=update_network_log_data,
                                                     args=(os_name, log_path, network_log_data_queue,)))
        log_and_alert_thread.append(threading.Thread(target=update_alert_queue,
                                                     args=(model, network_log_data_queue, alert_queue,)))
        for thread in log_and_alert_thread:
            thread.start()


def stop_log_and_alert():
    log_sniffer.sniffing = False
    log_sniffer.df_updating = False
