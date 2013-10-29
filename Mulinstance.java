
import weka.core.Instances;
import weka.classifiers.mi.*;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.PropositionalToMultiInstance;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import weka.classifiers.Evaluation;
import java.util.Random;

public class Mulinstance {


	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		BufferedReader reader;
		try {
			reader = new BufferedReader(new FileReader("out.arff"));
			Instances data = new Instances(reader);
			reader.close();
			// setting class attribute
			//Utils.splitOptions("-C 1.0 -L 0.0010 -P 1.0E-12 -N 0 -V -1 -W 1 -K \"weka.classifiers.functions.supportVector.PolyKernel -C 250007 -E 1.0\""));
			//String[] options = weka.core.Utils.splitOptions("-R 1");   
			data.setClassIndex(data.numAttributes() - 1);
			Filter fl=new PropositionalToMultiInstance();
			fl.setInputFormat(data);
			Instances newdata = Filter.useFilter(data, fl);
			// weka.classifiers.functions.SMO scheme = new weka.classifiers.functions.SMO();
			MISVM mSVM=new MISVM();
			//mSVM.setOptions(options);
			mSVM.buildClassifier(newdata);
			Evaluation eval = new Evaluation(newdata);
			eval.crossValidateModel(mSVM, newdata, 10, new Random(1));
			System.out.println(eval.toSummaryString("\nResults\n======\n", false));
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.print("hello!");

	}

}
