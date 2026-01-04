# Extension de la config locale pour l'Itération 1 ACRA
@load policy/tuning/json-logs.zeek

# On s'assure que les timestamps sont au format Unix (plus facile à parser en Python)
redef LogAscii::use_json = T;
redef Log::default_scope_sep = "_";

event zeek_init()
    {
    # Optionnel : On peut filtrer ici pour ne pas tout loguer si le réseau est trop chargé
    }