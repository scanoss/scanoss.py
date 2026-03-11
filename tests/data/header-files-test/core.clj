;; Copyright (c) Rich Hickey. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns myapp.core
  (:require [clojure.string :as str]
            [clojure.java.io :as io]
            [clojure.edn :as edn]
            [clojure.tools.logging :as log]))

(defn load-config
  "Load configuration from an EDN file.
   Returns a map of configuration values."
  [path]
  (try
    (with-open [reader (io/reader path)]
      (edn/read (java.io.PushbackReader. reader)))
    (catch Exception e
      (log/error e "Failed to load config from" path)
      {})))

(defn parse-request
  "Parse an HTTP request string into a map."
  [request-str]
  (let [lines (str/split-lines request-str)
        [method path version] (str/split (first lines) #"\s+")
        headers (->> (rest lines)
                     (take-while (complement str/blank?))
                     (map #(str/split % #":\s*" 2))
                     (filter #(= 2 (count %)))
                     (into {} (map (fn [[k v]] [(str/lower-case k) v]))))]
    {:method  method
     :path    path
     :version version
     :headers headers}))

(defn route-request
  "Route a request to the appropriate handler."
  [routes request]
  (let [handler (get-in routes [(:method request) (:path request)])]
    (if handler
      (handler request)
      {:status 404
       :body   "Not Found"})))

(defn start-server
  "Start the application server with the given configuration."
  [config]
  (let [port (get config :port 8080)
        host (get config :host "0.0.0.0")]
    (log/info "Starting server on" host ":" port)
    {:port   port
     :host   host
     :status :running}))

(defn -main
  "Application entry point."
  [& args]
  (let [config-path (or (first args) "config.edn")
        config (load-config config-path)]
    (log/info "Loaded configuration:" config)
    (start-server config)))