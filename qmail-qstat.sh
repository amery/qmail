cd QMAIL
messdirs=`echo queue/mess/* | wc -w`
messfiles=`find queue/mess/* -print | wc -w`
if test -d "queue/todo/0"
then
tododirs=`echo queue/todo/* | wc -w`
todofiles=`find queue/todo/* -print | wc -w`
else
tododirs=`echo queue/todo | wc -w`
todofiles=`find queue/todo -print | wc -w`
fi
echo messages in queue: `expr $messfiles - $messdirs`
echo messages in queue but not yet preprocessed: `expr $todofiles - $tododirs`
